package qcc;


import qcc.core.ForwardRecord;
import qcc.core.Tombstone;
import qcc.data.QccCanonicalWriter;
import qcc.util.Sha3;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.BiConsumer;

/**
 * NameState —— 由操作日志重放得出的全部状态。纯内存,不落盘。
 * ═══ 容器选择:为什么全部是 TreeMap ═══════════════════════════════
 * HashMap / ConcurrentHashMap 的迭代顺序取决于哈希值、容量和扩容历史,
 * 同一份数据在不同 JVM、不同插入顺序下可以不同,换成别的语言更是必然不同。
 * Merkle 根要遍历全部状态,顺序一变根就变 —— 这是跨实现分歧的头号来源。
 * 所以核心里禁止任何哈希容器,一律 TreeMap。
 * key 用小写 hex 字符串而不是 byte[]:小写 hex 的字典序与其对应字节数组的
 * 字节序完全一致,所以 TreeMap 的自然序就是协议要求的 byte-ascending,
 * 同时又能直接用 String 做 key。地址是 base58,同样按字节序比较。
 * ═══ 三张表 ═══════════════════════════════════════════════════════
 *   forward    nameHash → ForwardRecord      名字的状态
 *   reverse    address  → nameHash           全局唯一,一个地址只能属于一个账户
 *   tombstone  nameHash → Tombstone          已释放,含冷却期与下一代世代号
 * 不变量(四条,与链上协议 invariants 段一致):
 *   1. 名字全局唯一
 *   2. 一个地址至多属于一个账户(反向索引唯一)
 *   3. 每个账户至少绑定一个地址
 *   4. owner 永远指向一个当前已绑定的地址
 * 前两条由本类的 apply() 强制,后两条由 ForwardRecord 的构造器强制。
 */
public final class NameState {

    private final TreeMap<String, ForwardRecord> forward   = new TreeMap<>(NameState::byteOrder);
    private final TreeMap<String, String>        reverse   = new TreeMap<>(NameState::byteOrder);
    private final TreeMap<String, Tombstone>     tombstone = new TreeMap<>(NameState::byteOrder);
    /** 同形字归一化索引:normHash → nameHash。防 0/o、1/l、rn/m 这类视觉仿冒。 */
    private final TreeMap<String, String>        confusable = new TreeMap<>(NameState::byteOrder);

    /** 按 UTF-8 字节序比较,不用 String 的 UTF-16 码元序。 */
    private static int byteOrder(String a, String b) {
        return QccCanonicalWriter.compareUtf8(a, b);
    }

    // ── 查询 ──────────────────────────────────────────────────────

    public ForwardRecord forward(String nameHashHex) { return forward.get(nameHashHex); }
    public String        reverse(String address)     { return reverse.get(address); }
    public Tombstone     tombstone(String nameHashHex) { return tombstone.get(nameHashHex); }
    /** 归一化后已被谁占用。返回 null 表示无冲突。 */
    public String        confusableOwner(String normHashHex) { return confusable.get(normHashHex); }

    public boolean nameTaken(String nameHashHex)  { return forward.containsKey(nameHashHex); }
    public boolean addressTaken(String address)   { return reverse.containsKey(address); }

    public int nameCount()    { return forward.size(); }
    public int addressCount() { return reverse.size(); }
    public int tombCount()    { return tombstone.size(); }
    public int confusableCount() { return confusable.size(); }

    /** 名字下一次注册应使用的世代号:从未注册过是 1,释放过则用墓碑里的值。 */
    public long nextIncarnation(String nameHashHex) {
        Tombstone t = tombstone.get(nameHashHex);
        return t == null ? 1L : t.nextIncarnation;
    }

    // ── 变更:只能通过 apply(StateDelta) ───────────────────────────

    /**
     * 应用一条变更集。这是修改状态的**唯一**入口 —— handler 不直接碰这三张表,
     * 它们只产出 StateDelta。这样"进 execHash 的东西"和"实际改变状态的东西"
     * 在结构上就是同一个对象,不可能出现两者不一致。
     */
    public void apply(StateDelta delta) {
        for (StateDelta.Entry e : delta.entries()) {
            switch (e.type()) {
                case StateDelta.PUT_FORWARD -> forward.put(e.key(), ForwardRecord.decode(e.value()));
                case StateDelta.DEL_FORWARD -> {
                    if (forward.remove(e.key()) == null)
                        throw new IllegalStateException("DEL_FORWARD 目标不存在: " + e.key());
                }
                case StateDelta.PUT_REVERSE -> {
                    String nameHash = new String(e.value(), StandardCharsets.UTF_8);
                    String prev = reverse.put(e.key(), nameHash);
                    if (prev != null && !prev.equals(nameHash))
                        throw new IllegalStateException(
                                "违反不变量 2:地址 " + e.key() + " 已属于另一个账户 " + prev);
                }
                case StateDelta.DEL_REVERSE -> {
                    if (reverse.remove(e.key()) == null)
                        throw new IllegalStateException("DEL_REVERSE 目标不存在: " + e.key());
                }
                case StateDelta.PUT_TOMBSTONE -> tombstone.put(e.key(), Tombstone.decode(e.value()));
                case StateDelta.PUT_CONFUSABLE -> {
                    String nameHash = new String(e.value(), StandardCharsets.UTF_8);
                    String prev = confusable.put(e.key(), nameHash);
                    if (prev != null && !prev.equals(nameHash))
                        throw new IllegalStateException(
                                "归一化名冲突:" + e.key() + " 已属于 " + prev);
                }
                case StateDelta.DEL_CONFUSABLE -> {
                    if (confusable.remove(e.key()) == null)
                        throw new IllegalStateException("DEL_CONFUSABLE 目标不存在: " + e.key());
                }
                default -> throw new IllegalStateException("未知的 delta 类型: " + e.type());
            }
        }
    }

    // ── Merkle 叶子:确定顺序遍历 ──────────────────────────────────

    /**
     * 按规范顺序遍历全部状态叶子,供 SparseMerkle 计算 stateRoot。
     *
     * 顺序:先 forward(按 nameHash 字节序),再 reverse(按地址字节序),
     * 最后 tombstone(按 nameHash 字节序)。三段之间用类型前缀区分,
     * 避免不同类型的 key 碰撞成同一个叶子。
     *
     * leaf = SHA3-256(0x00 || typeCode || key || canonical(value))
     * 与链上协议 state.merkle.leaf 一致(这里在 key 前多了一个 typeCode,
     * 因为协议里的 key 是逻辑 key,而三张表共用一棵树时必须带类型)。
     */
    public void forEachLeaf(BiConsumer<byte[], byte[]> fn) {
        for (Map.Entry<String, ForwardRecord> e : forward.entrySet())
            fn.accept(leafKey(StateDelta.PUT_FORWARD, e.getKey()),
                      leafValue(StateDelta.PUT_FORWARD, e.getKey(), e.getValue().encode()));
        for (Map.Entry<String, String> e : reverse.entrySet())
            fn.accept(leafKey(StateDelta.PUT_REVERSE, e.getKey()),
                      leafValue(StateDelta.PUT_REVERSE, e.getKey(),
                                e.getValue().getBytes(StandardCharsets.UTF_8)));
        for (Map.Entry<String, Tombstone> e : tombstone.entrySet())
            fn.accept(leafKey(StateDelta.PUT_TOMBSTONE, e.getKey()),
                      leafValue(StateDelta.PUT_TOMBSTONE, e.getKey(), e.getValue().encode()));
        for (Map.Entry<String, String> e : confusable.entrySet())
            fn.accept(leafKey(StateDelta.PUT_CONFUSABLE, e.getKey()),
                      leafValue(StateDelta.PUT_CONFUSABLE, e.getKey(),
                                e.getValue().getBytes(StandardCharsets.UTF_8)));
    }

    /** 叶子在稀疏树里的位置 = SHA3(typeCode || key)。 */
    public static byte[] leafKey(int type, String key) {
        return Sha3.hash(new QccCanonicalWriter().u8(type).str(key).toBytes());
    }

    public static byte[] leafValue(int type, String key, byte[] value) {
        return Sha3.hash(new byte[]{0x00},
                new QccCanonicalWriter().u8(type).str(key).bytes(value).toBytes());
    }

    /**
     * 全量状态摘要 —— 排序哈希链。
     * 这是 Merkle 树做出来之前的临时 stateRoot,也是一个独立的交叉校验:
     * 两个节点如果 Merkle 根一致而这个值不一致,说明 Merkle 实现有 bug。
     */
    public byte[] flatRoot() {
        byte[][] acc = { Sha3.zero32() };
        forEachLeaf((k, v) -> acc[0] = Sha3.hash(acc[0], k, v));
        return acc[0];
    }

    public String flatRootHex() { return Sha3.toHex(flatRoot()); }

    @Override
    public String toString() {
        return "NameState{names=" + forward.size()
                + " addrs=" + reverse.size()
                + " tombs=" + tombstone.size()
                + " conf=" + confusable.size() + "}";
    }
}
