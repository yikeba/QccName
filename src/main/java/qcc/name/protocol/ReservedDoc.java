package qcc.name.protocol;

import qcc.name.codec.QccCanonicalWriter;
import qcc.name.codec.Sha3;
import qcc.name.crypto.QccAddress;

import java.util.*;

/**
 * Reserved 文档（保留名表）—— 协议发布者以 QCCData 交易发布到 QCC 公链，每一版都是完整的表。
 *
 * <pre>
 * {
 *   "protocol": "qcc-name-reserved",
 *   "version": "1.0.0",
 *   "nameProtocolHash": "&lt;qcc-name 协议 hash&gt;",
 *   "seq": 2,
 *   "prevTx": "&lt;上一版的交易 hash，首版为空串&gt;",
 *   "names": { "admin.osn": "Q…", "support.osn": "Q…", "security.osn": "" },
 *   "release": ["test.osn"]
 * }
 * </pre>
 *
 * 本类只做结构解析（字段集合、类型、名称与地址格式）；与上一版、与协议 tags / label 规则的核对在确定性核心里做。
 * 解析失败抛 IllegalArgumentException。
 */
public final class ReservedDoc {

    public static final String PROTOCOL = "qcc-name-reserved";
    public static final String VERSION  = "1.0.0";
    private static final Set<String> KEYS = Set.of("protocol", "version", "nameProtocolHash", "seq", "prevTx", "names", "release");

    public final String nameProtocolHash;
    public final long   seq;
    public final String prevTx;
    /** 全名 → 地址；空串 = 保留但暂不绑定。按 UTF-8 字节序，遍历确定。 */
    public final SortedMap<String, String> names;
    public final SortedSet<String> release;
    public final String documentHash;

    private ReservedDoc(String nph, long seq, String prevTx, SortedMap<String, String> names, SortedSet<String> release, String hash) {
        this.nameProtocolHash = nph; this.seq = seq; this.prevTx = prevTx;
        this.names = Collections.unmodifiableSortedMap(names);
        this.release = Collections.unmodifiableSortedSet(release);
        this.documentHash = hash;
    }

    public static ReservedDoc parse(byte[] raw) {
        try {
            if (raw.length >= 3 && (raw[0] & 0xFF) == 0xEF && (raw[1] & 0xFF) == 0xBB && (raw[2] & 0xFF) == 0xBF)
                throw new IllegalArgumentException("含 BOM");
            for (byte b : raw) if (b == '\r') throw new IllegalArgumentException("含 CR，只允许 LF");
            Map<String, Object> m = StrictJson.parseObject(raw);
            StrictJson.rejectUnknown(m, KEYS, "Reserved");
            for (String k : KEYS) if (!m.containsKey(k)) throw new IllegalArgumentException("缺少字段 " + k);
            if (!PROTOCOL.equals(StrictJson.str(m, "protocol"))) throw new IllegalArgumentException("protocol 必须是 " + PROTOCOL);
            if (!VERSION.equals(StrictJson.str(m, "version")))   throw new IllegalArgumentException("version 必须是 " + VERSION);
            String nph = StrictJson.str(m, "nameProtocolHash");
            if (!NameProtocol.isLowerHex64(nph)) throw new IllegalArgumentException("nameProtocolHash 必须是 64 位小写 hex");
            long seq = StrictJson.num(m, "seq");
            if (seq < 1) throw new IllegalArgumentException("seq 从 1 开始");
            String prev = StrictJson.strAllowEmpty(m, "prevTx");
            if (!prev.isEmpty() && !NameProtocol.isLowerHex64(prev)) throw new IllegalArgumentException("prevTx 必须为空串或 64 位小写 hex");

            TreeMap<String, String> names = new TreeMap<>(QccCanonicalWriter::compareUtf8);
            Map<String, Object> n = StrictJson.obj(m, "names");
            for (String k : n.keySet()) {
                checkName(k);
                Object v = n.get(k);
                if (!(v instanceof String a)) throw new IllegalArgumentException("names." + k + " 必须是地址字符串或空串");
                if (!a.isEmpty() && !QccAddress.isValid(a)) throw new IllegalArgumentException("names." + k + " 不是有效地址: " + a);
                names.put(k, a);
            }
            TreeSet<String> rel = new TreeSet<>(QccCanonicalWriter::compareUtf8);
            for (String r : StrictJson.strArr(m, "release")) {
                checkName(r);
                if (!rel.add(r)) throw new IllegalArgumentException("release 重复: " + r);
                if (names.containsKey(r)) throw new IllegalArgumentException("release 与 names 同时出现: " + r);
            }
            return new ReservedDoc(nph, seq, prev, names, rel, Sha3.toHex(Sha3.hash(raw)));
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    /** 结构：恰好一个 '.'，label 与 tag 均为 [a-z0-9-] 非空。长度、首尾连字符等按协议在核心里查。 */
    static void checkName(String s) {
        int dot = s.indexOf('.');
        if (dot <= 0 || dot != s.lastIndexOf('.') || dot == s.length() - 1 || s.length() > 96)
            throw new IllegalArgumentException("名称必须形如 label.tag: " + s);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.'))
                throw new IllegalArgumentException("名称只允许小写 a-z、0-9、-: " + s);
        }
    }

    public static String labelOf(String name) { return name.substring(0, name.indexOf('.')); }
    public static String tagOf(String name)   { return name.substring(name.indexOf('.') + 1); }
}
