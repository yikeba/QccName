package qcc.name.chain;

/** 授权质押查询结果。exists=false 时其余字段无意义。from = 授权发起方（资产钱包）。 */
public record PledgeFact(boolean exists, String assetId, long amount, String from) {
    public static PledgeFact none() { return new PledgeFact(false, "", 0L, ""); }
}
