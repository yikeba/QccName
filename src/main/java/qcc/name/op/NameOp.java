package qcc.name.op;

import qcc.name.codec.QccCanonicalReader;
import qcc.name.codec.QccCanonicalWriter;
import qcc.name.codec.Sha3;

import java.nio.charset.StandardCharsets;

/**
 * NameOp —— 用户签名的 namespace 操作（注册 / 删除）的抽象基类。
 *
 * ═══ 两种形态，职责不同（仿 TransactionData）════════════════════
 *   toSign()   签名字符串：value-only、SIGN_SEP 分隔、固定字段顺序。
 *              客户端（Flutter / Java）对 toSign().getBytes(UTF-8) 做 ML-DSA-87 签名。
 *              跨语言零依赖：只需要字符串拼接。
 *   toBytes()  二进制形态：放进 NameFrame、写进帧日志、参与 execHash。
 *              验签时从二进制还原对象 → 重新派生 toSign() → 验签。
 *              两种形态由同一组字段确定性派生，不存在"签的和存的不是同一个东西"。
 *
 * ═══ 签名字符串字段顺序（冻结，改动必须换 DOMAIN）══════════════
 *   DOMAIN | opName | chain | address | name | timestamp | <子类字段...>
 *   register:   ... | credentialHash
 *   unregister: ... | regSeq
 *   expire:     ... | credentialHash      （系统操作，不签名；address = 原持有地址，timestamp = chainTime）
 *
 * ═══ 防重放 ════════════════════════════════════════════════════
 *   不设 nonce。确定性核心为每个 address 记 lastTs，新操作 timestamp 必须
 *   严格大于它；进入日志的操作（OK 或 REJECTED）都推进 lastTs。
 *   入口层另查 |timestamp - 墙钟| ≤ 5 分钟（不进日志，不参与回放）。
 *
 * ═══ 本类只做结构校验 ═════════════════════════════════════════
 *   字段非空、无保留字符、name 形如 label.tag 且为小写 ASCII。
 *   长度 2–32、保留名、同形字、冷却期等**策略**检查在确定性核心里按 TagPolicy 做。
 */
public abstract class NameOp {

    /** 域隔离前缀：与 QCC 交易及其它用途的签名区分开。语义变更必须改这里。 */
    public static final String DOMAIN = "QNS1";

    /**
     * 签名字符串分隔符。
     * 【假设，需确认】QCC 的 QccBaseData.SIGN_SEP 未提供，这里先用 "|"。
     * 若要与 QCC 钱包共用同一个分隔符，改这一行即可（name/address/hex 均不含 "|"）。
     */
    public static final String SIGN_SEP = "|";

    /** 二进制形态的魔数，与 DOMAIN 同步变更。 */
    static final byte[] MAGIC = DOMAIN.getBytes(StandardCharsets.US_ASCII);

    public static final int TYPE_REGISTER   = 0x01;
    public static final int TYPE_UNREGISTER = 0x02;
    /** 系统操作：质押失效后由主节点回收名称，无用户签名。 */
    public static final int TYPE_EXPIRE     = 0x03;
    /** 系统操作：协议发布者的 Reserved 文档生效，无用户签名，name 为空串。 */
    public static final int TYPE_RESERVE    = 0x04;

    // 结构上限（不是策略：策略长度由 TagPolicy 决定，这里只防畸形输入）
    static final int MAX_LABEL_LEN   = 63;
    static final int MAX_TAG_LEN     = 32;
    static final int MAX_CHAIN_LEN   = 16;
    static final int MIN_ADDRESS_LEN = 25;
    static final int MAX_ADDRESS_LEN = 64;

    private static final String BASE58 =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // ── 公共字段 ──────────────────────────────────────────────────
    public final String chain;      // "6666" 测试 / "9999" 主网，与 TransactionData.getChain() 一致
    public final String address;    // Q 地址（被授权的 0 资产钱包），签名者
    public final String name;       // 完整名称 label.tag，已规范化（小写 ASCII）
    public final long   timestamp;  // 毫秒

    protected NameOp(String chain, String address, String name, long timestamp) {
        this.chain = chain;
        this.address = address;
        this.name = name;
        this.timestamp = timestamp;
    }

    // ── 子类实现 ──────────────────────────────────────────────────
    public abstract int    typeCode();
    /** 本操作是否由 address 的私钥签名。expire 是系统操作，返回 false。 */
    public boolean userSigned() { return true; }
    /** 本操作是否针对一个名称（name 必须形如 label.tag）。reserve 返回 false，name 为空串。 */
    protected boolean named() { return true; }
    public abstract String opName();
    /** 子类字段追加到签名字符串（每个字段前自带 SIGN_SEP）。 */
    protected abstract void appendSignFields(StringBuilder sb);
    /** 子类字段写入二进制。 */
    protected abstract void writeTail(QccCanonicalWriter w);
    /** 子类字段的结构校验。 */
    protected abstract void validateTail();

    // ── 签名字符串 ────────────────────────────────────────────────

    public final String toSign() {
        validate();
        StringBuilder sb = new StringBuilder(160);
        sb.append(DOMAIN)
          .append(SIGN_SEP).append(opName())
          .append(SIGN_SEP).append(chain)
          .append(SIGN_SEP).append(address)
          .append(SIGN_SEP).append(name)
          .append(SIGN_SEP).append(timestamp);
        appendSignFields(sb);
        return sb.toString();
    }

    /** ML-DSA-87 签名/验签的输入字节。 */
    public final byte[] signBytes() {
        return toSign().getBytes(StandardCharsets.UTF_8);
    }

    /** 操作哈希 = SHA3-256(signBytes)。用于幂等查重与日志索引。 */
    public final String opHash() {
        return Sha3.toHex(Sha3.hash(signBytes()));
    }

    /** 拿到对象后重新派生签名字符串，与收到的逐字节比对（仿 TransactionData.verifySignString）。 */
    public final boolean verifySignString(String received) {
        return toSign().equals(received);
    }

    // ── 二进制形态 ────────────────────────────────────────────────
    //   MAGIC(4) | u8(type) | str(chain) | str(address) | str(name) | u64(timestamp) | tail

    public final byte[] toBytes() {
        validate();
        QccCanonicalWriter w = new QccCanonicalWriter(160)
                .fixed(MAGIC, MAGIC.length)
                .u8(typeCode())
                .str(chain)
                .str(address)
                .str(name)
                .u64(timestamp);
        writeTail(w);
        return w.toBytes();
    }

    /** 从二进制还原。未知类型、尾部多余字节、结构非法一律抛异常。 */
    public static NameOp fromBytes(byte[] b) {
        QccCanonicalReader r = new QccCanonicalReader(b);
        byte[] magic = r.fixed(MAGIC.length);
        for (int i = 0; i < MAGIC.length; i++)
            if (magic[i] != MAGIC[i]) throw new IllegalArgumentException("NameOp MAGIC 不符");
        int type      = r.u8();
        String chain  = r.str();
        String addr   = r.str();
        String name   = r.str();
        long ts       = r.u64();
        NameOp op = switch (type) {
            case TYPE_REGISTER   -> new RegisterOp(chain, addr, name, ts, r.hash32Hex());
            case TYPE_UNREGISTER -> new UnregisterOp(chain, addr, name, ts, r.u64());
            case TYPE_EXPIRE     -> new ExpireOp(chain, addr, name, ts, r.hash32Hex());
            case TYPE_RESERVE    -> {
                if (!name.isEmpty()) throw new IllegalArgumentException("reserve 的 name 必须为空串");
                yield new ReserveOp(chain, addr, ts, r.hash32Hex(), r.u64(), r.bytes());
            }
            default -> throw new IllegalArgumentException("未知 NameOp 类型: " + type);
        };
        r.finish();
        op.validate();
        return op;
    }

    // ── 结构校验 ──────────────────────────────────────────────────

    public final void validate() {
        requireToken("chain", chain, MAX_CHAIN_LEN);
        for (int i = 0; i < chain.length(); i++) {
            char c = chain.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')))
                throw new IllegalArgumentException("chain 含非法字符: " + chain);
        }

        requireToken("address", address, MAX_ADDRESS_LEN);
        if (address.length() < MIN_ADDRESS_LEN)
            throw new IllegalArgumentException("address 过短: " + address);
        for (int i = 0; i < address.length(); i++)
            if (BASE58.indexOf(address.charAt(i)) < 0)
                throw new IllegalArgumentException("address 含非 Base58 字符: " + address);
        // 【假设】checksum 校验未做：QCC 地址 checksum 算法（AddressTool）未提供。
        // 入口层按地址从链上取公钥，取不到即拒绝，非法地址在那一步自然被拦下。

        if (named()) validateName(name);
        else if (name == null || !name.isEmpty()) throw new IllegalArgumentException(opName() + " 的 name 必须为空串");

        if (timestamp <= 0) throw new IllegalArgumentException("timestamp 必须为正");
        validateTail();
    }

    /** name 结构：恰好一个 '.'，label 与 tag 均为 [a-z0-9-]，非空。 */
    static void validateName(String name) {
        if (name == null || name.isEmpty()) throw new IllegalArgumentException("name 为空");
        int dot = name.indexOf('.');
        if (dot <= 0 || dot != name.lastIndexOf('.') || dot == name.length() - 1)
            throw new IllegalArgumentException("name 必须形如 label.tag: " + name);
        String label = name.substring(0, dot);
        String tag   = name.substring(dot + 1);
        if (label.length() > MAX_LABEL_LEN) throw new IllegalArgumentException("label 过长: " + name);
        if (tag.length()   > MAX_TAG_LEN)   throw new IllegalArgumentException("tag 过长: " + name);
        checkLowerAscii(label, name);
        checkLowerAscii(tag, name);
    }

    private static void checkLowerAscii(String s, String full) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
                throw new IllegalArgumentException("name 只允许小写 a-z、0-9、- : " + full);
        }
    }

    static void requireToken(String field, String v, int maxLen) {
        if (v == null || v.isEmpty()) throw new IllegalArgumentException(field + " 为空");
        if (v.length() > maxLen) throw new IllegalArgumentException(field + " 过长");
        if (v.contains(SIGN_SEP) || v.indexOf('\n') >= 0 || v.indexOf('\r') >= 0)
            throw new IllegalArgumentException(field + " 含保留字符");
    }

    // ── 便捷访问 ──────────────────────────────────────────────────

    public final String label() { return name.substring(0, name.indexOf('.')); }
    public final String tag()   { return name.substring(name.indexOf('.') + 1); }

    @Override
    public final boolean equals(Object o) {
        return o instanceof NameOp other && java.util.Arrays.equals(toBytes(), other.toBytes());
    }

    @Override
    public final int hashCode() { return java.util.Arrays.hashCode(toBytes()); }

    @Override
    public String toString() { return toSign(); }
}
