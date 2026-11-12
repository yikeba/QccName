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
 */
public record VerifyResult(Status status, String name, String address, long regSeq, String credentialHash,
                           long asOfSeq, int term, String nodeId, byte[] opBytes, byte[] signature) {

    public enum Status { MATCH, MISMATCH, NOT_FOUND, REVOKED, UNVERIFIED }

    public boolean match() { return status == Status.MATCH; }
}
