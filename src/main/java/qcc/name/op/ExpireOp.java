package qcc.name.op;

import qcc.name.codec.QccCanonicalWriter;
import qcc.name.codec.Sha3;

/**
 * 质押失效回收（系统操作，无用户签名）。
 *
 *   QNS1|expire|{chain}|{address}|{name}|{timestamp}|{credentialHash}
 *
 * 惰性触发：注册撞上 nameTaken / addrHasName 时，主节点去链上查原持有者的
 * 授权质押；已不存在（发起方撤销）则先写一条 expire 帧回收，再处理当前请求。
 *   address        = 被回收名称的持有地址
 *   timestamp      = 主节点写帧时的 chainTime（不推进该地址的 lastTs）
 *   credentialHash = 被回收那次注册所用的授权凭证，绑定到"某一次具体的注册"
 *
 * 可验证性（v1.0 / L1）：QCC 质押是内存状态机，撤销后链上不留历史，
 * 回放者只能核对"该凭证现在也不存在"。撤销是单调的（凭证 hash 不会复活），
 * 所以若回放时凭证仍存在，即证明这条 expire 是伪造的。
 */
public final class ExpireOp extends NameOp {

    public final String credentialHash;

    public ExpireOp(String chain, String address, String name, long timestamp, String credentialHash) {
        super(chain, address, name, timestamp);
        this.credentialHash = credentialHash;
    }

    @Override public int     typeCode()   { return TYPE_EXPIRE; }
    @Override public String  opName()     { return "expire"; }
    @Override public boolean userSigned() { return false; }

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
        if (credentialHash == null || credentialHash.length() != 64 || !Sha3.isHex32(credentialHash)
                || !credentialHash.equals(credentialHash.toLowerCase(java.util.Locale.ROOT)))
            throw new IllegalArgumentException("credentialHash 必须是 64 位小写 hex");
    }
}
