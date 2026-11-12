package qcc.name.protocol;

/**
 * 一个名称 tag（如 qcc、osn、com）的注册策略，来自引导协议的 tags 字段。
 * 质押统一查 params.pledgeTag（qccio）下的授权质押，资产与门槛按名称 tag 区分。
 *
 * 协议本身不内置保留名。registration = open：开放注册、先到先得；reserved：不开放自助注册，
 * 该 tag 下的名字只由协议发布者的 Reserved 文档分配（见 ReservedDoc）。
 */
public record TagPolicy(String tag, String assetId, long minAmount, boolean open) {

    /** registration 字段：open = 开放注册；reserved = 不开放自助注册，名字只来自 Reserved（企业级 namespace）。 */
    public static final String OPEN = "open", RESERVED_ONLY = "reserved";

    public boolean pledgeMet(boolean exists, String asset, long amount) {
        return exists && assetId.equals(asset) && amount >= minAmount;
    }
}
