package qcc.name.protocol;

import qcc.name.codec.Sha3;

/**
 * 引导协议加载器 —— 应用启动的第一步,也是唯一一处"信任根"。
 *
 * ── 硬编码的两个常量 ─────────────────────────────────────────────
 * PROTOCOL_TX_HASH  去链上哪儿取(定位)
 * PROTOCOL_HASH     取到的是不是那一份(验证),同时是 execHash0 的输入
 *
 * 两个必须都有,而且用途不能互换:
 *   - TX_HASH 覆盖了 timestamp / from / assetId 等信封字段,同一份协议
 *     字节重发一次就会变,不能当协议身份。
 *   - PROTOCOL_HASH 是 payload 原始字节的 SHA3-256,只要字节一样就一样,
 *     这才是协议身份。
 *
 * ── 为什么不做"运行时发现最新版本" ────────────────────────────────
 * 如果应用启动时去问"这个 managementAddr 最新发布了哪个协议",那么信任根
 * 就变成了那把私钥,单点。硬编码 hash 之后,信任根是 hash 本身:
 * 换协议 = 换 hash = 必须发新版应用 = 开源可见 = 用户可以拒绝升级。
 * 配合发布地址的 AddressEnd 死亡交易,协议在链上永久不可变。
 *
 * ── 网络解耦 ──────────────────────────────────────────────────
 * 本类不直接依赖 HTTP。Fetcher 由调用方注入,原因是验证者要能离线重放:
 * 他手上已经有 payload 字节(从任何渠道拿到的),只需要校验 hash 就能加载
 * 完全相同的 ProtocolRoot,不需要能访问任何节点。
 */
public final class ProtocolLoader {

    /** 链上定位:qcc-name v1 的存证交易 hash。 */
    public static final String PROTOCOL_TX_HASH =
            "f1134cb5df74dc9256e5604a29322470c532edbd4186e18b24e10834242a8627";

    /** 协议身份:SHA3-256(payload 原始字节)。execHash0 的第一个输入。 */
    public static final String PROTOCOL_HASH =
            "dd6eba18d557b4c3a99d4355390021488e052c088f49465ca0f7894109dfcb51";

    /** 备用定位:hash 查询修复前,可按容器高度取。 */
    public static final long PROTOCOL_CONTAINER_HEIGHT = 342665L;

    /** 取回链上 payload 原始字节。实现方不得做任何裁剪、转码或重新序列化。 */
    @FunctionalInterface
    public interface Fetcher {
        byte[] fetchPayload(String txHash) throws Exception;
    }

    private ProtocolLoader() {}

    /** 生产路径:按硬编码常量从链上加载。 */
    public static ProtocolRoot loadPinned(Fetcher fetcher) {
        return load(fetcher, PROTOCOL_TX_HASH, PROTOCOL_HASH);
    }

    public static ProtocolRoot load(Fetcher fetcher, String txHash, String pinnedHash) {
        if (fetcher == null) throw new IllegalArgumentException("fetcher is null");
        requirePinnedHashShape(pinnedHash);
        byte[] payload;
        try {
            payload = fetcher.fetchPayload(txHash);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "无法从链上取回引导协议 tx=" + txHash + " —— 拒绝启动。" +
                    "节点不能在没有协议的情况下运行,任何默认值都会让边界失效。", e);
        }
        if (payload == null || payload.length == 0)
            throw new IllegalStateException("链上 payload 为空 tx=" + txHash);
        return loadFromBytes(payload, pinnedHash);
    }

    /**
     * 离线路径:字节已在手上(验证者重放、单元测试、灾备)。
     * 与在线路径产出完全相同的 ProtocolRoot —— 这是"独立可验证"的前提。
     */
    public static ProtocolRoot loadFromBytes(byte[] payload, String pinnedHash) {
        requirePinnedHashShape(pinnedHash);
        String actual = Sha3.toHex(Sha3.hash(payload));
        if (!actual.equalsIgnoreCase(pinnedHash)) {
            throw new IllegalStateException(
                    "引导协议 hash 不匹配 —— 拒绝启动。\n" +
                    "  硬编码 : " + pinnedHash + "\n" +
                    "  实际   : " + actual + "  (" + payload.length + " 字节)\n" +
                    "  提示   : 最常见的原因是 payload 在传输/复制过程中被裁剪了首尾空白。" +
                    "先比对字节数,再看首尾字节。");
        }
        // ProtocolRoot.load 内部会再算一次 hash 并做严格解析(缺字段/多字段都失败)。
        // 这里重复校验是有意的:让错误消息在这一层就带上字节数和诊断提示。
        return ProtocolRoot.load(payload, actual);
    }

    private static void requirePinnedHashShape(String h) {
        if (!Sha3.isHex32(h))
            throw new IllegalArgumentException("pinnedHash 必须是 64 字符 hex: " + h);
    }

    /**
     * execHash0 = SHA3-256(protocolHash || instanceId || genesisBlockHeight)
     *
     * instanceId 取该实例根 tag 的 TagRule 交易 hash —— 链上唯一、天然绑定运营方。
     * 加 instanceId 是为了让两个不同部署即使操作日志巧合相同,execHash 也不同,
     * 避免一个实例的 epoch header 被拿去冒充另一个实例。
     */
    public static byte[] genesisExecHash(ProtocolRoot root, String instanceIdHex, long genesisHeight) {
        if (genesisHeight < 0) throw new IllegalArgumentException("genesisHeight 不能为负: " + genesisHeight);
        return root.genesisExecHash(instanceIdHex, genesisHeight);
    }
}
