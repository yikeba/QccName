package qcc.name.chain;

import qcc.name.core.PledgeFact;

/**
 * 链上事实的读取接口。确定性核心通过它拿到质押、公钥、高度,
 * 但**核心自己不调用它** —— 调用发生在核心之外,结果作为 OpInput 传进去。
 *
 * 三个实现:
 *   HttpChainView      远程或本机 /v1/pledge、/v1/tag,生产用
 *   RecordedChainView  文件回放,验证者离线用,也让测试确定化
 *   一个组合式的 RecordingChainView 把前者的结果写成后者的文件
 *
 * 【为什么鉴权查当前状态是对的】
 * 撤销即时生效是这套设计的止血手柄。如果鉴权去查历史,撤销就失效了。
 * 所以 authPledge() 查的就是**此刻**的状态,不带高度。
 *
 * 【那重放怎么办】
 * register 的 payload 里带 credentialHash。重放者拿它按 hash 查链,
 * 得到质押交易的金额/资产/生效高度,再查有没有对应的解押交易,
 * 就能独立算出"当时是否合格",不需要相信 leader 记了什么。
 * 这个能力依赖 /v1/hash 查询(vault 初始化修好后可用)。
 */
public interface ChainView {

    /** 授权质押三要素查询,对应 PledgeRuleManager.hasAuthPledge 的语义。 */
    PledgeFact authPledge(String address, String tag, String credentialHash);

    /** 地址的 ML-DSA-87 公钥,用于验签。取不到返回 null。 */
    byte[] pubkeyOf(String address);

    /** 当前容器高度。admitHeight 的来源。 */
    long currentHeight();
}
