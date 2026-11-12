package qcc.name.node;

/**
 * 名称验证结果（对应 GET /v1/verify）。
 *
 * 对外只有一个结论：match() = true / false。status 只说明原因，不是第三种状态：
 *   MATCH       名称属于该地址，且注册所用的授权质押当前仍有效 → true
 *   MISMATCH    名称属于其他地址                                → false
 *   NOT_FOUND   名称不存在                                      → false
 *   REVOKED     名称属于该地址，但授权质押已撤销                → false（节点记录待下次冲突时回收）
 *   UNVERIFIED  查链失败，无法确认质押                          → false（确认不了就不放行）
 *
 * L1 证据：opBytes + signature 是用户当初的注册请求原文，
 * 任何人可以据此独立核对（见 qcc.name.verify.ResultVerifier），不必相信节点。
 * pubkey：链上没有该地址公钥（0 资产钱包）时给出，可为 null；核对方须确认它推导出该地址。
 *
 * reserved = true：名称在当前生效的 Reserved 表中，结论只按表给出（优先于注册信息，不查质押）。
 *   regSeq = 写入该表的 reserve 帧序号，opBytes = 该 reserve 操作（含完整文档），signature 为空，
 *   reservedTx = 文档所在链上交易：任何人可 GET /v1/hash/{reservedTx} 核对 from / 高度 / payload。
 */
public record VerifyResult(Status status, String name, String address, long regSeq, String credentialHash,
                           long asOfSeq, int term, String nodeId, byte[] opBytes, byte[] signature,
                           byte[] pubkey, boolean reserved, String reservedTx) {

    public enum Status { MATCH, MISMATCH, NOT_FOUND, REVOKED, UNVERIFIED }

    /** 注册名（非保留名）。 */
    public VerifyResult(Status status, String name, String address, long regSeq, String credentialHash,
                        long asOfSeq, int term, String nodeId, byte[] opBytes, byte[] signature, byte[] pubkey) {
        this(status, name, address, regSeq, credentialHash, asOfSeq, term, nodeId, opBytes, signature, pubkey, false, "");
    }

    public boolean match() { return status == Status.MATCH; }
}
