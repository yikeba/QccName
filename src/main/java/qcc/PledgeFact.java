package qcc.name.core;

/**
 * 从 QCC 链上取回的质押事实,作为**输入**喂给确定性核心。
 *
 * 核心不能自己查链 —— 那是 IO,而且实时查询的结果会随时间变化,重放就废了。
 * 所以查询在核心之外完成,结果作为 OpInput 的一部分传进来。
 *
 * 【可重放性的枢纽】ChainView 必须按 **blockHeight** 查询,而不是查"当前状态"。
 * 给定同一个高度,任何时候、任何节点查到的都是同一个答案(链已最终确定),
 * 所以验证者用同样的高度重查,拿到完全相同的事实,重放结果必然一致。
 * 核心里只要出现一处"查当前状态",独立验证就不成立了。
 */
public record PledgeFact(boolean exists, String assetId, long amount) {

    public static PledgeFact none() { return new PledgeFact(false, "", 0L); }

    public boolean satisfies(String requiredAsset, long minAmount) {
        return exists && requiredAsset.equals(assetId) && amount >= minAmount;
    }
}
