package qcc.name.protocol;

import qcc.name.codec.Sha3;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static qcc.name.protocol.StrictJson.*;

/**
 * qcc-name 引导协议的可执行形态。
 *
 * 只能通过 {@link #parse(byte[])} 构造：先算原始字节的 SHA3-256，再按
 * qcc-meta/1 的规则逐项检查结构，任何一项不符都抛异常 —— 节点拒绝启动，没有降级路径。
 *
 * 检查内容（对应 qcc-meta/1）：
 *   - 顶层字段集合必须与本实现认识的完全一致（未知字段致命、缺字段致命）
 *   - spec == qcc-meta/1 的 protocolHash
 *   - docs.zh / docs.en 键集合相同，且包含 requiredKeys；{path} 引用必须能解析
 *   - boundary 各项必须为 true
 *   - ops 必须恰好是本实现实现的三个操作，check 名称必须都已实现
 *   - resultCodes 必须覆盖本实现可能产出的全部结果码
 */
public final class NameProtocol {

    /** qcc-meta/1 在 QCC 测试链上的定位（tx 09ea70e0…，高度 16965）。 */
    public static final String META_TX_HASH = "09ea70e03fc68f5e4d8bba69b2228e27d72ba25955c33718b3a06a0df02bf2e8";
    public static final String META_HASH    = "a25375d6cf4feb2a3fc86afd553bdc8157991894ea6cd0e0bf14462557f46fdf";

    private static final Set<String> TOP = Set.of("spec", "protocol", "version", "prevProtocolHash",
            "status", "docs", "encoding", "verifiability", "params", "tags", "reserved", "op", "ops",
            "checkOrder", "resultCodes", "frame", "boundary");
    private static final Set<String> STATUS = Set.of("voluntary", "draft", "deprecated");
    private static final List<String> DOCS_REQUIRED = List.of("overview", "trustRoot", "boundary", "verifiability", "limits");
    private static final Set<String> PARAMS = Set.of("chain", "pledgeTag", "amountUnit", "labelMinLen", "labelMaxLen",
            "labelAlphabet", "labelNoLeadingHyphen", "labelNoTrailingHyphen", "confusableMap",
            "confusableAlgorithm", "cooldownMs", "entranceClockSkewMs", "minBackupAcks");
    private static final Set<String> BOUNDARY = Set.of("unknownFieldIsFatal", "missingFieldIsFatal", "noDefaults",
            "undeclaredOperationIsFatal", "unimplementedOperationIsFatal", "literalParametersForbidden", "noFallback");
    private static final Pattern REF = Pattern.compile("\\{([A-Za-z0-9_.]+)\\}");

    /** 本实现实现的操作：name → code。必须与协议 ops 完全一致。 */
    public static final Map<String, Integer> IMPLEMENTED_OPS = Map.of("register", 1, "unregister", 2, "expire", 3, "reserve", 4);

    public record OpSpec(int code, String name, boolean userSigned, List<String> checks, Set<Integer> loggedRejections) {}

    // ── 解析结果 ──────────────────────────────────────────────────
    public final String protocolHash;
    public final String version;
    public final String chain;
    public final String pledgeTag;
    public final int    labelMinLen;
    public final int    labelMaxLen;
    public final String labelAlphabet;
    public final boolean labelNoLeadingHyphen;
    public final boolean labelNoTrailingHyphen;
    public final SortedMap<String, String> confusableMap;
    public final long   cooldownMs;
    public final long   entranceClockSkewMs;
    public final int    minBackupAcks;
    public final SortedMap<String, TagPolicy> tags;
    public final SortedMap<Integer, OpSpec>   ops;
    public final SortedMap<Integer, String>   resultCodes;
    /** Reserved 文档最大字节数（协议 reserved.maxBytes）。 */
    public final int    reservedMaxBytes;
    /**
     * 保留名发布者 = 本协议所在 QCC 交易的 from。不在协议字节里（协议不能包含自己的交易信息），
     * 由节点用 protocolTx 从链上取得并核对 payload hash 后通过 {@link #withReservedPublisher} 设入；
     * 空串 = 未配置 protocolTx，Reserved 关闭，所有 tag 完全开放。参与 genesisExecHash，节点之间不一致会立即分叉报警。
     */
    public final String reservedPublisher;
    private final byte[] raw;

    private NameProtocol(byte[] raw) { this(raw, ""); }

    private NameProtocol(byte[] raw, String reservedPublisher) {
        this.raw = raw.clone();
        if (!reservedPublisher.isEmpty() && !qcc.name.crypto.QccAddress.isValid(reservedPublisher))
            throw err("保留名发布者不是有效地址: " + reservedPublisher);
        this.reservedPublisher = reservedPublisher;
        this.protocolHash = Sha3.toHex(Sha3.hash(raw));
        if (raw.length >= 3 && (raw[0] & 0xFF) == 0xEF && (raw[1] & 0xFF) == 0xBB && (raw[2] & 0xFF) == 0xBF)
            throw err("协议含 BOM");
        for (byte b : raw) if (b == '\r') throw err("协议含 CR，只允许 LF");

        Map<String, Object> m = parseObject(raw);
        exactKeys(m, TOP, "顶层");

        if (!str(m, "spec").equals(META_HASH)) throw err("spec 不是 qcc-meta/1 的 hash");
        if (!str(m, "protocol").equals("qcc-name")) throw err("protocol 必须是 qcc-name");
        this.version = str(m, "version");
        if (!version.matches("(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)")) throw err("version 格式错误");
        String prev = str(m, "prevProtocolHash");
        if (!isLowerHex64(prev)) throw err("prevProtocolHash 必须是 64 位小写 hex");
        if (!STATUS.contains(str(m, "status"))) throw err("status 非法");
        str(m, "checkOrder");

        checkDocs(m);
        checkEncoding(obj(m, "encoding"));
        checkVerifiability(obj(m, "verifiability"));

        Map<String, Object> b = obj(m, "boundary");
        exactKeys(b, BOUNDARY, "boundary");
        for (String k : BOUNDARY) if (!bool(b, k)) throw err("boundary." + k + " 必须为 true");

        Map<String, Object> p = obj(m, "params");
        exactKeys(p, PARAMS, "params");
        this.chain = str(p, "chain");
        this.pledgeTag = str(p, "pledgeTag");
        str(p, "amountUnit");
        this.labelMinLen = positiveInt(p, "labelMinLen");
        this.labelMaxLen = positiveInt(p, "labelMaxLen");
        if (labelMinLen > labelMaxLen) throw err("labelMinLen > labelMaxLen");
        this.labelAlphabet = str(p, "labelAlphabet");
        for (char c : labelAlphabet.toCharArray())
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
                throw err("labelAlphabet 只能是 NameOp 结构允许的字符子集");
        this.labelNoLeadingHyphen = bool(p, "labelNoLeadingHyphen");
        this.labelNoTrailingHyphen = bool(p, "labelNoTrailingHyphen");
        TreeMap<String, String> cm = new TreeMap<>();
        Map<String, Object> rawMap = obj(p, "confusableMap");
        for (String k : rawMap.keySet()) {
            if (k.isEmpty()) throw err("confusableMap 不允许空 key");
            cm.put(k, str(rawMap, k));
        }
        this.confusableMap = Collections.unmodifiableSortedMap(cm);
        str(p, "confusableAlgorithm");
        this.cooldownMs = nonNegative(p, "cooldownMs");
        this.entranceClockSkewMs = nonNegative(p, "entranceClockSkewMs");
        this.minBackupAcks = (int) nonNegative(p, "minBackupAcks");

        this.tags = parseTags(obj(m, "tags"));
        this.reservedMaxBytes = parseReserved(obj(m, "reserved"));
        checkOpSection(obj(m, "op"));
        this.ops = parseOps(arr(m, "ops"));
        this.resultCodes = parseResultCodes(obj(m, "resultCodes"));
        checkFrame(obj(m, "frame"));

        for (int code : qcc.name.core.ResultCode.ALL)
            if (!resultCodes.containsKey(code))
                throw err("本实现会产出 resultCode " + code + "，协议未定义 —— 拒绝启动");
        for (OpSpec op : ops.values())
            for (int c : op.loggedRejections())
                if (!resultCodes.containsKey(c)) throw err("loggedRejections 含未定义的结果码 " + c);

        resolveDocReferences(m);
    }

    public static NameProtocol parse(byte[] raw) { return new NameProtocol(raw); }

    /** 同一份协议，设定保留名发布者（链上协议交易的 from）。 */
    public NameProtocol withReservedPublisher(String publisher) { return new NameProtocol(raw, publisher); }

    public boolean reservedEnabled() { return !reservedPublisher.isEmpty(); }

    public TagPolicy tag(String tag) { return tags.get(tag); }

    public OpSpec op(int code) { return ops.get(code); }

    // ── 各段检查 ──────────────────────────────────────────────────

    private static void checkDocs(Map<String, Object> m) {
        Map<String, Object> d = obj(m, "docs");
        exactKeys(d, Set.of("note", "zh", "en"), "docs");
        str(d, "note");
        Map<String, Object> zh = obj(d, "zh"), en = obj(d, "en");
        if (!zh.keySet().equals(en.keySet())) throw err("docs.zh 与 docs.en 键集合不同");
        for (String k : DOCS_REQUIRED) if (!zh.containsKey(k)) throw err("docs 缺少必需键 " + k);
        for (String k : zh.keySet()) { str(zh, k); str(en, k); }
    }

    private static void checkEncoding(Map<String, Object> e) {
        exactKeys(e, Set.of("self", "hashAlg", "hashInput", "reEncodingForbidden",
                "byteOrderMarkForbidden", "lineEnding", "note"), "encoding");
        if (!str(e, "self").equals("json-utf8")) throw err("encoding.self");
        if (!str(e, "hashAlg").equals("SHA3-256")) throw err("encoding.hashAlg");
        str(e, "hashInput"); str(e, "note");
        if (!bool(e, "reEncodingForbidden") || !bool(e, "byteOrderMarkForbidden")) throw err("encoding 标志必须为 true");
        if (!str(e, "lineEnding").equals("LF")) throw err("encoding.lineEnding");
    }

    private static void checkVerifiability(Map<String, Object> v) {
        exactKeys(v, Set.of("level", "evidence"), "verifiability");
        if (!str(v, "level").equals("L1")) throw err("本实现只达到 L1，协议声明的等级必须是 L1");
        Map<String, Object> ev = obj(v, "evidence");
        exactKeys(ev, Set.of("register", "reserve", "note"), "verifiability.evidence");
        strArr(ev, "register"); strArr(ev, "reserve"); str(ev, "note");
    }

    private static SortedMap<String, TagPolicy> parseTags(Map<String, Object> t) {
        if (t.isEmpty()) throw err("tags 为空");
        TreeMap<String, TagPolicy> out = new TreeMap<>();
        for (String tag : t.keySet()) {
            if (!tag.matches("[a-z0-9-]{1,32}")) throw err("tag 名非法: " + tag);
            @SuppressWarnings("unchecked") Map<String, Object> p = (Map<String, Object>) t.get(tag);
            exactKeys(p, Set.of("assetId", "minAmount"), "tags." + tag);
            long min = num(p, "minAmount");
            if (min < 1) throw err("tags." + tag + ".minAmount 必须 ≥ 1");
            out.put(tag, new TagPolicy(tag, str(p, "assetId"), min));
        }
        return Collections.unmodifiableSortedMap(out);
    }

    private static int parseReserved(Map<String, Object> r) {
        exactKeys(r, Set.of("spec", "maxBytes", "publisher", "document", "rules", "resolution", "effectiveAt"), "reserved");
        if (!str(r, "spec").equals(ReservedDoc.PROTOCOL)) throw err("reserved.spec 必须是 " + ReservedDoc.PROTOCOL);
        long max = num(r, "maxBytes");
        if (max < 1024 || max > 512 * 1024) throw err("reserved.maxBytes 越界（1KB–512KB）");
        str(r, "publisher"); str(r, "document"); str(r, "rules"); str(r, "resolution"); str(r, "effectiveAt");
        return (int) max;
    }

    private static void checkOpSection(Map<String, Object> o) {
        exactKeys(o, Set.of("magic", "signSeparator", "signString", "signature", "binary"), "op");
        if (!str(o, "magic").equals(qcc.name.op.NameOp.DOMAIN)) throw err("op.magic 与实现不符");
        if (!str(o, "signSeparator").equals(qcc.name.op.NameOp.SIGN_SEP)) throw err("op.signSeparator 与实现不符");
        Map<String, Object> ss = obj(o, "signString");
        exactKeys(ss, Set.of("register", "unregister", "expire", "reserve"), "op.signString");
        for (String k : ss.keySet()) str(ss, k);
        str(o, "signature"); str(o, "binary");
    }

    private static SortedMap<Integer, OpSpec> parseOps(List<Object> list) {
        TreeMap<Integer, OpSpec> out = new TreeMap<>();
        Set<String> names = new TreeSet<>();
        for (Object x : list) {
            @SuppressWarnings("unchecked") Map<String, Object> o = (Map<String, Object>) x;
            exactKeys(o, Set.of("code", "name", "userSigned", "checks", "loggedRejections", "effect"), "ops[]");
            int code = (int) num(o, "code");
            String name = str(o, "name");
            Integer impl = IMPLEMENTED_OPS.get(name);
            if (impl == null) throw err("协议声明了本实现未实现的操作 " + name + " —— 拒绝启动");
            if (impl != code) throw err("操作 " + name + " 的 code 与实现不符");
            List<String> checks = strArr(o, "checks");
            for (String c : checks)
                if (!qcc.name.core.NameMachine.IMPLEMENTED_CHECKS.contains(c))
                    throw err("协议要求检查项 " + c + "，本实现没有 —— 拒绝启动");
            TreeSet<Integer> logged = new TreeSet<>();
            for (Object c : arr(o, "loggedRejections")) {
                if (!(c instanceof Long)) throw err("loggedRejections 元素必须是整数");
                logged.add(((Long) c).intValue());
            }
            str(o, "effect");
            out.put(code, new OpSpec(code, name, bool(o, "userSigned"), checks, Collections.unmodifiableSet(logged)));
            names.add(name);
        }
        if (!names.equals(IMPLEMENTED_OPS.keySet())) throw err("本实现的操作 " + IMPLEMENTED_OPS.keySet() + " 未全部在协议中声明");
        return Collections.unmodifiableSortedMap(out);
    }

    private static SortedMap<Integer, String> parseResultCodes(Map<String, Object> rc) {
        TreeMap<Integer, String> out = new TreeMap<>();
        for (String k : rc.keySet()) {
            if (!k.matches("0|[1-9][0-9]{0,2}")) throw err("resultCodes key 非法: " + k);
            int c = Integer.parseInt(k);
            if (c > 255) throw err("resultCode 必须 ≤ 255（帧里是 u8）");
            out.put(c, str(rc, k));
        }
        return Collections.unmodifiableSortedMap(out);
    }

    private static void checkFrame(Map<String, Object> f) {
        exactKeys(f, Set.of("magic", "types", "data", "sigHash", "execHash", "genesisExecHash",
                "signaturesStoredSeparately", "seqStartsAt", "seqContiguous"), "frame");
        if (!str(f, "magic").equals(qcc.name.frame.FrameCodec.MAGIC_STR)) throw err("frame.magic 与实现不符");
        Map<String, Object> t = obj(f, "types");
        exactKeys(t, Set.of("1", "2", "3", "4"), "frame.types");
        for (String k : t.keySet()) str(t, k);
        str(f, "data"); str(f, "sigHash"); str(f, "execHash"); str(f, "genesisExecHash");
        if (!bool(f, "signaturesStoredSeparately") || !bool(f, "seqContiguous")) throw err("frame 标志必须为 true");
        if (num(f, "seqStartsAt") != 1) throw err("frame.seqStartsAt 必须为 1");
    }

    /** docs 中的 {path} 引用必须解析到一个标量（字符串/整数/布尔）。 */
    private static void resolveDocReferences(Map<String, Object> root) {
        Map<String, Object> d = obj(root, "docs");
        for (String lang : List.of("zh", "en")) {
            Map<String, Object> l = obj(d, lang);
            for (String k : l.keySet()) {
                Matcher mt = REF.matcher(str(l, k));
                while (mt.find()) {
                    Object v = root;
                    for (String seg : mt.group(1).split("\\.")) {
                        if (!(v instanceof Map<?, ?> mm) || !mm.containsKey(seg))
                            throw err("docs." + lang + "." + k + " 的引用 {" + mt.group(1) + "} 无法解析");
                        v = mm.get(seg);
                    }
                    if (v instanceof Map || v instanceof List)
                        throw err("docs 引用 {" + mt.group(1) + "} 不是标量");
                }
            }
        }
    }

    /** 渲染 docs：把 {path} 替换为机器字段的值。供展示工具使用。 */
    public static String renderDoc(byte[] raw, String lang, String key) {
        Map<String, Object> root = parseObject(raw);
        String text = str(obj(obj(root, "docs"), lang), key);
        Matcher mt = REF.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (mt.find()) {
            Object v = root;
            for (String seg : mt.group(1).split("\\.")) v = ((Map<?, ?>) v).get(seg);
            mt.appendReplacement(sb, Matcher.quoteReplacement(String.valueOf(v)));
        }
        mt.appendTail(sb);
        return sb.toString();
    }

    // ── 工具 ──────────────────────────────────────────────────────

    private static void exactKeys(Map<String, Object> m, Set<String> expected, String where) {
        rejectUnknown(m, expected, where);
        for (String k : expected) if (!m.containsKey(k)) throw err("缺少字段 " + where + "." + k);
    }

    private static int positiveInt(Map<String, Object> m, String k) {
        long v = num(m, k);
        if (v < 1 || v > Integer.MAX_VALUE) throw err(k + " 越界");
        return (int) v;
    }

    private static long nonNegative(Map<String, Object> m, String k) {
        long v = num(m, k);
        if (v < 0) throw err(k + " 不能为负");
        return v;
    }

    static boolean isLowerHex64(String s) {
        return s.length() == 64 && s.chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }

    private static IllegalStateException err(String msg) {
        return new IllegalStateException("[NameProtocol] " + msg);
    }

    public byte[] protocolHashBytes() { return Sha3.fromHex32(protocolHash); }

    @Override
    public String toString() {
        return "qcc-name " + version + " hash=" + protocolHash.substring(0, 16) + "… tags=" + tags.keySet()
                + " chain=" + chain + " pledgeTag=" + pledgeTag
                + (reservedEnabled() ? " reservedPublisher=" + reservedPublisher : " Reserved=关闭");
    }

    static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }
}
