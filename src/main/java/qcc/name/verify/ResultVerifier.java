package qcc.name.verify;

import qcc.name.chain.ChainView;
import qcc.name.chain.PledgeFact;
import qcc.name.crypto.MlDsa87;
import qcc.name.crypto.QccAddress;
import qcc.name.node.VerifyResult;
import qcc.name.op.NameOp;
import qcc.name.op.RegisterOp;
import qcc.name.protocol.NameProtocol;
import qcc.name.protocol.TagPolicy;

import java.util.ArrayList;
import java.util.List;

/**
 * L1 结果核对：不信任节点，只用节点给出的证据 + QCC 公链，独立判断一个 MATCH 结果是否真实。
 *
 *   1. opBytes 是一条 RegisterOp，name / address / credentialHash 与结果一致
 *   2. 用链上公钥验证用户签名（签的是 opBytes 派生出的签名字符串）
 *   3. 授权质押现在仍然存在，且满足该 tag 的策略
 *
 * 不能证明的（协议 docs.limits 已写明）：节点是否拒绝或延迟过别人的请求、先到先得的顺序。
 */
public final class ResultVerifier {

    public record Report(boolean ok, List<String> lines) {}

    private ResultVerifier() {}

    public static Report check(VerifyResult r, NameProtocol p, ChainView chain) {
        List<String> out = new ArrayList<>();
        if (!r.match()) { out.add("结果不是 MATCH，无需核对证据"); return new Report(false, out); }
        boolean ok = true;

        NameOp op;
        try { op = NameOp.fromBytes(r.opBytes()); }
        catch (RuntimeException e) { out.add("✗ opBytes 无法解析"); return new Report(false, out); }

        if (!(op instanceof RegisterOp reg)) { out.add("✗ 证据不是注册请求"); return new Report(false, out); }
        boolean same = reg.name.equals(r.name()) && reg.address.equals(r.address())
                && reg.credentialHash.equals(r.credentialHash()) && reg.chain.equals(p.chain);
        out.add((same ? "✓" : "✗") + " 证据中的 name/address/credentialHash/chain 与结果一致");
        ok &= same;

        byte[] pk = chain.pubkeyOf(reg.address);
        String src = "链上公钥";
        if (pk == null && r.pubkey() != null) {                   // 0 资产钱包：用证据里的公钥，但必须推导出该地址
            boolean bound = QccAddress.matches(r.pubkey(), reg.address);
            out.add((bound ? "✓" : "✗") + " 证据公钥推导出的地址与 address 一致（链上无该地址公钥）");
            ok &= bound;
            if (bound) { pk = r.pubkey(); src = "证据公钥"; }
        }
        boolean sigOk = pk != null && MlDsa87.verify(pk, reg.signBytes(), r.signature());
        out.add((sigOk ? "✓" : "✗") + " 用户签名有效（" + src + "）");
        ok &= sigOk;

        PledgeFact pf = chain.authPledge(reg.address, p.pledgeTag, reg.credentialHash);
        TagPolicy t = p.tag(reg.tag());
        boolean pledgeOk = t != null && t.pledgeMet(pf.exists(), pf.assetId(), pf.amount());
        out.add((pledgeOk ? "✓" : "✗") + " 授权质押当前存在且满足 " + reg.tag() + " 策略"
                + (pf.exists() ? "（" + pf.amount() + " " + pf.assetId() + "，发起方 " + pf.from() + "）" : "（已不存在）"));
        ok &= pledgeOk;
        return new Report(ok, out);
    }
}
