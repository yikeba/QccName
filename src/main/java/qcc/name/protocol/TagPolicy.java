package qcc.name.protocol;

/**
 * 一个名称 tag（如 qcc、osn、com）的注册策略，来自引导协议的 tags 字段。
 * 质押统一查 params.pledgeTag（qccio）下的授权质押，资产与门槛按名称 tag 区分。
 *
 * 协议本身不内置保留名：tag 完全开放、先到先得。保留名由协议发布者另行发布 Reserved 文档（见 ReservedDoc）。
 */
public record TagPolicy(String tag, String assetId, long minAmount) {

    public boolean pledgeMet(boolean exists, String asset, long amount) {
        return exists && assetId.equals(asset) && amount >= minAmount;
    }
}
