package qcc.name.op;

import qcc.name.codec.QccCanonicalWriter;
import qcc.name.codec.Sha3;

/**
 * 注册操作。
 *
 * 签名字符串：
 *   QNS1|register|{chain}|{address}|{name}|{timestamp}|{credentialHash}
 *
 * credentialHash = 授权质押（AuthorizedPledge lock）交易的 txHash。
 * 主节点用三要素 (address, 质押 tag, credentialHash) 查 /v1/pledge，
 * 质押事实（assetId、amount）写进帧，按 TagPolicy 判定。
 * credentialHash 在签名覆盖范围内，回放者据此去链上核对。
 */
public final class RegisterOp extends NameOp {

    /** 64 位小写 hex。 */
    public final String credentialHash;

    public RegisterOp(String chain, String address, String name, long timestamp,
                      String credentialHash) {
        super(chain, address, name, timestamp);
        this.credentialHash = credentialHash;
    }

    @Override public int    typeCode() { return TYPE_REGISTER; }
    @Override public String opName()   { return "register"; }

    @Override
    protected void appendSignFields(StringBuilder sb) {
        sb.append(SIGN_SEP).append(credentialHash);
    }

    @Override
    protected void writeTail(QccCanonicalWriter w) {
        w.hash32Hex(credentialHash);
    }

    @Override
    protected void validateTail() {
        if (credentialHash == null || credentialHash.length() != 64 || !Sha3.isHex32(credentialHash))
            throw new IllegalArgumentException("credentialHash 必须是 64 位 hex");
        // 签名字符串与二进制往返必须一致：二进制还原出的是小写 hex，
        // 若允许大写，签名方签的是大写串、验签方派生的是小写串 → 验签必败。
        if (!credentialHash.equals(credentialHash.toLowerCase(java.util.Locale.ROOT)))
            throw new IllegalArgumentException("credentialHash 必须是小写 hex");
    }
}
