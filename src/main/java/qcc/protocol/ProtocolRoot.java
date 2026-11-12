package qcc.name.protocol;

import qcc.name.codec.Sha3;

import java.util.*;

/**
 * 引导协议的可执行形态 —— 应用程序边界的落地点。
 *
 * ═══ 三条硬约束(全部导致启动失败,没有降级路径)═══════════════════
 *   1. 无默认值      字段缺失即失败,绝不回退
 *   2. 未知字段致命  协议里有程序不认识的字段,说明 jar 比协议旧
 *   3. hash 自校验   链上取回的字节必须匹配硬编码的 PROTOCOL_HASH
 *
 * ═══ 为什么参数必须从这里注入 ═══════════════════════════════════
 * 如果 maxAddressesPerName 这些值以字面量写在代码里,那么链上那份协议
 * 就只是一份文档,真正决定行为的是 jar。运营方改个常量重新发包,
 * 所有 hash 依然自洽,没人察觉。
 *
 * 参数从协议注入之后:改参数必须发新协议 → 换 protocolHash → execHash0
 * 变化 → 创世断裂 → 改动无法隐藏。人工审计的范围也从"整个程序"缩小到
 * "控制流逻辑"。
 *
 * 配套约束(CI 的 ArchUnit 规则):qcc.name.core 包内禁止出现除 0/1
 * 之外的数字字面量,状态机的构造器只接受本对象。
 */
public final class ProtocolRoot {

    private static final String SPEC_ID = "qcc-exec/1";

    private static final Set<String> TOP_LEVEL = Set.of(
            "spec", "protocol", "version", "prevProtocolHash",
            "encoding", "genesis", "execCodec", "time", "state", "params",
            "ops", "checkOrder", "resultCodes", "execHash", "epoch",
            "leader", "anchor", "receipt", "verify", "boundary");

    private static final Set<String> PARAM_KEYS = Set.of(
            "nameCharset", "nameNoLeadingHyphen", "nameNoTrailingHyphen",
            "nameNoConsecutiveHyphen", "nameConfusableMap", "maxAddressesPerName",
            "pledgeAssetId", "pledgeMinAmount", "releaseCooldownBlocks",
            "tombstoneRetentionBlocks");

    private static final Set<String> OP_KEYS = Set.of("code", "name", "signers", "checks", "effect");

    private final byte[] rawBytes;          // 链上原文,execHash0 的输入,永不丢弃
    private final String protocolHash;
    private final String protocol;
    private final String version;
    private final String prevProtocolHash;

    private final Params params;
    private final List<OpSpec> ops;
    private final Map<Integer, String> resultCodes;
    private final long    antiReplayWindowBlocks;
    private final String  epochCloseOn;
    private final String  execHashFormula;
    private final boolean execHashIncludesRejected;

    // ── 加载 ──────────────────────────────────────────────────────

    public static ProtocolRoot load(byte[] onChainPayload, String pinnedHash) {
        String actual = Sha3.toHex(Sha3.hash(onChainPayload));
        if (!actual.equalsIgnoreCase(pinnedHash))
            throw new IllegalStateException(
                    "protocol hash 不匹配 —— 拒绝启动\n  pinned : " + pinnedHash
                    + "\n  实际   : " + actual + " (" + onChainPayload.length + " 字节)");
        return parseStrict(onChainPayload, actual);
    }

    private static ProtocolRoot parseStrict(byte[] raw, String hash) {
        Map<String, Object> p = StrictJson.parseObject(raw);
        StrictJson.rejectUnknown(p, TOP_LEVEL, "<root>");

        if (!SPEC_ID.equals(StrictJson.str(p, "spec")))
            throw new IllegalStateException("不支持的 spec,本实现只认识 " + SPEC_ID);

        Map<String, Object> bd = StrictJson.obj(p, "boundary");
        if (!StrictJson.bool(bd, "unknownFieldIsFatal")
         || !StrictJson.bool(bd, "missingFieldIsFatal")
         || !StrictJson.bool(bd, "noDefaults"))
            throw new IllegalStateException("boundary 的三个开关必须全为 true");

        if (!"SHA3-256".equals(StrictJson.str(StrictJson.obj(p, "encoding"), "hashAlg")))
            throw new IllegalStateException("protocolHash 只支持 SHA3-256");

        Map<String, Object> tm = StrictJson.obj(p, "time");
        if (!"qcc-block-height".equals(StrictJson.str(tm, "source")))
            throw new IllegalStateException("time.source 必须是 qcc-block-height —— 墙钟不可重放");
        if (!StrictJson.bool(tm, "wallClockForbidden"))
            throw new IllegalStateException("time.wallClockForbidden 必须为 true");

        Map<String, Object> ec = StrictJson.obj(p, "execCodec");
        if (!StrictJson.bool(ec, "jsonForbidden"))
            throw new IllegalStateException("execCodec.jsonForbidden 必须为 true");
        if (!"reject".equals(StrictJson.str(ec, "intOverflow")))
            throw new IllegalStateException("execCodec.intOverflow 必须是 reject");

        Map<String, Object> eh = StrictJson.obj(p, "execHash");
        Map<String, Object> ep = StrictJson.obj(p, "epoch");

        return new ProtocolRoot(
                raw.clone(), hash,
                StrictJson.str(p, "protocol"),
                StrictJson.str(p, "version"),
                StrictJson.strAllowEmpty(p, "prevProtocolHash"),
                Params.of(StrictJson.obj(p, "params")),
                parseOps(StrictJson.arr(p, "ops")),
                parseResultCodes(StrictJson.obj(p, "resultCodes")),
                StrictJson.num(tm, "antiReplayWindowBlocks"),
                StrictJson.str(ep, "closeOn"),
                StrictJson.str(eh, "perOp"),
                StrictJson.bool(eh, "includesRejected"));
    }

    // ── 参数(不可变) ────────────────────────────────────────────

    public record Params(
            String nameCharset,
            boolean nameNoLeadingHyphen,
            boolean nameNoTrailingHyphen,
            boolean nameNoConsecutiveHyphen,
            Map<String, String> nameConfusableMap,
            int  maxAddressesPerName,
            String pledgeAssetId,
            long pledgeMinAmount,
            long releaseCooldownBlocks,
            long tombstoneRetentionBlocks) {

        static Params of(Map<String, Object> o) {
            StrictJson.rejectUnknown(o, PARAM_KEYS, "params");
            Map<String, Object> cm = StrictJson.obj(o, "nameConfusableMap");
            // TreeMap:遍历顺序确定,绝不用 HashMap
            Map<String, String> conf = new TreeMap<>();
            for (Map.Entry<String, Object> e : cm.entrySet()) {
                if (!(e.getValue() instanceof String))
                    throw new IllegalStateException("nameConfusableMap 的值必须是字符串");
                conf.put(e.getKey(), (String) e.getValue());
            }
            long maxAddr = StrictJson.num(o, "maxAddressesPerName");
            if (maxAddr < 1 || maxAddr > Integer.MAX_VALUE)
                throw new IllegalStateException("maxAddressesPerName 越界: " + maxAddr);
            return new Params(
                    StrictJson.str(o, "nameCharset"),
                    StrictJson.bool(o, "nameNoLeadingHyphen"),
                    StrictJson.bool(o, "nameNoTrailingHyphen"),
                    StrictJson.bool(o, "nameNoConsecutiveHyphen"),
                    Collections.unmodifiableMap(conf),
                    (int) maxAddr,
                    StrictJson.str(o, "pledgeAssetId"),
                    StrictJson.num(o, "pledgeMinAmount"),
                    StrictJson.num(o, "releaseCooldownBlocks"),
                    StrictJson.num(o, "tombstoneRetentionBlocks"));
        }
    }

    /** 操作定义。checks 的**顺序**是协议的一部分 —— 它决定 resultCode,进 execHash。 */
    public record OpSpec(int code, String name, List<String> signers, List<String> checks, String effect) {}

    private static List<OpSpec> parseOps(List<Object> arr) {
        if (arr.isEmpty()) throw new IllegalStateException("ops 不能为空");
        List<OpSpec> out = new ArrayList<>();
        Set<Integer> seenCode = new TreeSet<>();
        Set<String>  seenName = new TreeSet<>();
        for (int i = 0; i < arr.size(); i++) {
            if (!(arr.get(i) instanceof Map)) throw new IllegalStateException("ops[" + i + "] 不是对象");
            @SuppressWarnings("unchecked")
            Map<String, Object> o = (Map<String, Object>) arr.get(i);
            StrictJson.rejectUnknown(o, OP_KEYS, "ops[" + i + "]");
            long codeL = StrictJson.num(o, "code");
            if (codeL < 0 || codeL > 255) throw new IllegalStateException("op code 必须在 0..255: " + codeL);
            int code = (int) codeL;
            String name = StrictJson.str(o, "name");
            if (!seenCode.add(code)) throw new IllegalStateException("重复的 op code: " + code);
            if (!seenName.add(name)) throw new IllegalStateException("重复的 op name: " + name);
            out.add(new OpSpec(code, name,
                    StrictJson.strArr(o, "signers"),
                    StrictJson.strArr(o, "checks"),
                    StrictJson.str(o, "effect")));
        }
        return List.copyOf(out);
    }

    private static Map<Integer, String> parseResultCodes(Map<String, Object> o) {
        Map<Integer, String> m = new TreeMap<>();
        for (Map.Entry<String, Object> e : o.entrySet()) {
            int k;
            try { k = Integer.parseInt(e.getKey()); }
            catch (NumberFormatException ex) {
                throw new IllegalStateException("resultCode key 不是整数: " + e.getKey());
            }
            if (!(e.getValue() instanceof String))
                throw new IllegalStateException("resultCode 值必须是字符串");
            m.put(k, (String) e.getValue());
        }
        if (!"ok".equals(m.get(0))) throw new IllegalStateException("resultCode 0 必须是 'ok'");
        return Collections.unmodifiableMap(m);
    }

    // ── 分发表:协议决定哪些 op 存在,代码只提供实现 ──────────────

    public <H> Map<Integer, H> buildDispatch(Map<String, H> implByName) {
        Map<Integer, H> table = new TreeMap<>();
        for (OpSpec spec : ops) {
            H h = implByName.get(spec.name());
            if (h == null)
                throw new IllegalStateException("协议声明了操作 '" + spec.name()
                        + "' 但本实现没有对应实现 —— 拒绝启动");
            table.put(spec.code(), h);
        }
        for (String implemented : new TreeSet<>(implByName.keySet()))
            if (ops.stream().noneMatch(s -> s.name().equals(implemented)))
                throw new IllegalStateException("本实现有操作 '" + implemented
                        + "' 但协议未声明 —— 拒绝启动");
        return Collections.unmodifiableMap(table);
    }

    /** execHash0 = SHA3-256(protocolHash || instanceId || genesisBlockHeight) */
    public byte[] genesisExecHash(String instanceIdHex, long genesisBlockHeight) {
        if (genesisBlockHeight < 0) throw new IllegalArgumentException("高度不能为负");
        byte[] h = new byte[8];
        for (int i = 0; i < 8; i++) h[i] = (byte) (genesisBlockHeight >>> ((7 - i) * 8));
        return Sha3.hash(Sha3.fromHex32(protocolHash), Sha3.fromHex32(instanceIdHex), h);
    }

    // ── 构造与只读访问 ────────────────────────────────────────────

    private ProtocolRoot(byte[] rawBytes, String protocolHash, String protocol, String version,
                         String prevProtocolHash, Params params, List<OpSpec> ops,
                         Map<Integer, String> resultCodes, long antiReplayWindowBlocks,
                         String epochCloseOn, String execHashFormula,
                         boolean execHashIncludesRejected) {
        this.rawBytes = rawBytes; this.protocolHash = protocolHash;
        this.protocol = protocol; this.version = version;
        this.prevProtocolHash = prevProtocolHash; this.params = params;
        this.ops = ops; this.resultCodes = resultCodes;
        this.antiReplayWindowBlocks = antiReplayWindowBlocks;
        this.epochCloseOn = epochCloseOn; this.execHashFormula = execHashFormula;
        this.execHashIncludesRejected = execHashIncludesRejected;
    }

    public byte[] rawBytes()                  { return rawBytes.clone(); }
    public String protocolHash()              { return protocolHash; }
    public String protocol()                  { return protocol; }
    public String version()                   { return version; }
    public String prevProtocolHash()          { return prevProtocolHash; }
    public Params params()                    { return params; }
    public List<OpSpec> ops()                 { return ops; }
    public Map<Integer, String> resultCodes() { return resultCodes; }
    public long   antiReplayWindowBlocks()    { return antiReplayWindowBlocks; }
    public String epochCloseOn()              { return epochCloseOn; }
    public String execHashFormula()           { return execHashFormula; }
    public boolean execHashIncludesRejected() { return execHashIncludesRejected; }

    @Override
    public String toString() {
        return protocol + " v" + version + " [" + protocolHash.substring(0, 16) + "..]";
    }
}
