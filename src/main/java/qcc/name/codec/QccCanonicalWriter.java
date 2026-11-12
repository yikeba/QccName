package qcc.name.codec;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeMap;

/**
 * qcc-canonical-binary/1 —— 规范二进制写入器。
 *
 * 规范来自链上引导协议 execCodec 段(protocolHash
 * dd6eba18d557b4c3a99d4355390021488e052c088f49465ca0f7894109dfcb51):
 *
 *   intWidth      64
 *   intEndian     big
 *   intOverflow   reject
 *   stringEncoding UTF-8
 *   lengthPrefix  uint32-be
 *   mapOrder      sorted-by-key-bytes
 *   jsonForbidden true
 *
 * 【核心不变量】同一个逻辑对象,在任何语言、任何平台、任何时刻,
 * 必须产出完全相同的字节。所有进入 execHash 和 Merkle 叶子的数据
 * 都只能经由本类编码。
 *
 * 与 QccBaseData 的 write* 系列的三点差异,都是有意为之:
 *   1. writeHash32 对长度不足的 hex **抛异常**,而不是补 32 个零。
 *      静默补零会让多个不同的 key 塌缩到同一个哈希。
 *   2. writeString 对 null 与空串产出**不同**字节(0xFFFFFFFF vs 0x00000000),
 *      否则 {a:null} 与 {a:""} 编码相同,状态可以被伪造成另一个状态。
 *   3. 所有变长字段都带 uint32-be 长度前缀,段与段之间无歧义,
 *      因此 Sha3.hash(part1, part2, ...) 拼接是安全的。
 */
public final class QccCanonicalWriter {

    /** 单个变长字段的上限。防止构造出来的巨型字段撑爆内存。 */
    public static final int MAX_FIELD = 16 * 1024 * 1024;

    /** null 的长度前缀哨兵。真实长度永远 <= MAX_FIELD,不会冲突。 */
    static final int NULL_LEN = 0xFFFFFFFF;

    private final ByteArrayOutputStream buf;

    public QccCanonicalWriter() { this(256); }

    public QccCanonicalWriter(int initialCapacity) {
        this.buf = new ByteArrayOutputStream(initialCapacity);
    }

    // ── 定长 ──────────────────────────────────────────────────────

    public QccCanonicalWriter u8(int v) {
        if (v < 0 || v > 0xFF) throw new IllegalArgumentException("u8 越界: " + v);
        buf.write(v);
        return this;
    }

    public QccCanonicalWriter bool(boolean v) { return u8(v ? 1 : 0); }

    public QccCanonicalWriter u32(long v) {
        if (v < 0 || v > 0xFFFFFFFFL) throw new IllegalArgumentException("u32 越界: " + v);
        buf.write((int) (v >>> 24));
        buf.write((int) (v >>> 16));
        buf.write((int) (v >>> 8));
        buf.write((int) v);
        return this;
    }

    /** 有符号 64 位,大端。协议规定 intWidth=64。 */
    public QccCanonicalWriter i64(long v) {
        for (int i = 56; i >= 0; i -= 8) buf.write((int) (v >>> i));
        return this;
    }

    /**
     * 非负 64 位。协议 intOverflow=reject:负值不是"环绕",是错误。
     * 高度、序号、金额、incarnation 全部走这个。
     */
    public QccCanonicalWriter u64(long v) {
        if (v < 0) throw new IllegalArgumentException("u64 不接受负值: " + v);
        return i64(v);
    }

    /** 定长原始字节,不带长度前缀。仅用于长度已由上下文固定的场合。 */
    public QccCanonicalWriter fixed(byte[] b, int expectedLen) {
        if (b == null || b.length != expectedLen)
            throw new IllegalArgumentException(
                    "定长字段需要 " + expectedLen + " 字节,实际 " + (b == null ? "null" : b.length));
        buf.write(b, 0, b.length);
        return this;
    }

    /** 32 字节哈希,不带长度前缀。 */
    public QccCanonicalWriter hash32(byte[] h) { return fixed(h, Sha3.HASH_LEN); }

    /**
     * 64 字符 hex 的哈希。长度不对直接抛 —— 绝不补零。
     * 这是 QccBaseData.writeHash 那个坑的修正版。
     */
    public QccCanonicalWriter hash32Hex(String hex) { return hash32(Sha3.fromHex32(hex)); }

    // ── 变长 ──────────────────────────────────────────────────────

    /** uint32-be 长度前缀 + 原始字节。null 与空数组编码不同。 */
    public QccCanonicalWriter bytes(byte[] b) {
        if (b == null) { return u32raw(NULL_LEN); }
        if (b.length > MAX_FIELD)
            throw new IllegalArgumentException("字段超过 MAX_FIELD: " + b.length);
        u32(b.length);
        buf.write(b, 0, b.length);
        return this;
    }

    /** UTF-8,永不使用平台默认字符集。 */
    public QccCanonicalWriter str(String s) {
        return bytes(s == null ? null : s.getBytes(StandardCharsets.UTF_8));
    }

    /** 变长字节数组的数组:先写元素个数,再逐个 bytes()。 */
    public QccCanonicalWriter list(java.util.List<byte[]> items) {
        if (items == null) return u32raw(NULL_LEN);
        u32(items.size());
        for (byte[] it : items) bytes(it);
        return this;
    }

    public QccCanonicalWriter strList(java.util.List<String> items) {
        if (items == null) return u32raw(NULL_LEN);
        u32(items.size());
        for (String s : items) str(s);
        return this;
    }

    /**
     * map:按 key 的 **UTF-8 字节序**升序写出,与插入顺序无关。
     * 传进来的即使是 HashMap 也没关系 —— 这里强制重排。
     * 这条是"禁止依赖哈希容器迭代顺序"那条纪律的落地点。
     */
    public QccCanonicalWriter sortedMap(Map<String, byte[]> m) {
        if (m == null) return u32raw(NULL_LEN);
        TreeMap<String, byte[]> sorted = new TreeMap<>(QccCanonicalWriter::compareUtf8);
        sorted.putAll(m);
        u32(sorted.size());
        for (Map.Entry<String, byte[]> e : sorted.entrySet()) {
            str(e.getKey());
            bytes(e.getValue());
        }
        return this;
    }

    /** 按 UTF-8 字节序比较,而不是 Java 的 UTF-16 码元序。两者对补充平面字符结果不同。 */
    public static int compareUtf8(String a, String b) {
        byte[] x = a.getBytes(StandardCharsets.UTF_8);
        byte[] y = b.getBytes(StandardCharsets.UTF_8);
        int n = Math.min(x.length, y.length);
        for (int i = 0; i < n; i++) {
            int c = (x[i] & 0xFF) - (y[i] & 0xFF);
            if (c != 0) return c;
        }
        return x.length - y.length;
    }

    private QccCanonicalWriter u32raw(int v) {
        buf.write(v >>> 24);
        buf.write(v >>> 16);
        buf.write(v >>> 8);
        buf.write(v);
        return this;
    }

    // ── 输出 ──────────────────────────────────────────────────────

    public byte[] toBytes() { return buf.toByteArray(); }

    public int size() { return buf.size(); }

    /** 便捷:直接对写入内容取 SHA3-256。 */
    public byte[] sha3() { return Sha3.hash(toBytes()); }

    public String sha3Hex() { return Sha3.toHex(sha3()); }
}
