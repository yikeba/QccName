package qcc.name.chain;

/**
 * namespace 对 QCC 公链的全部依赖。只在确定性核心之外调用，结果写进帧。
 */
public interface ChainView {

    /** 授权质押三要素查询：被授权地址 + tag + 授权交易 hash。查不到返回 exists=false。 */
    PledgeFact authPledge(String address, String tag, String credentialHash) throws ChainUnavailableException;

    /** 地址的 2592 字节裸公钥；链上没有返回 null。 */
    byte[] pubkeyOf(String address) throws ChainUnavailableException;

    /** 当前链时间（毫秒）。主节点写帧时取一次，写进帧的 chainTime。 */
    long chainTime() throws ChainUnavailableException;

    /**
     * 回收名称（expire）前使用：质押"确认不存在"。expire 会写帧删除别人的名称、不可撤回，
     * 不能因为某个落后的链节点暂时查不到就判定撤销。多节点实现要求多个节点一致确认；单节点实现等同 !exists。
     */
    default boolean pledgeGoneConfirmed(String address, String tag, String credentialHash) throws ChainUnavailableException {
        return !authPledge(address, tag, credentialHash).exists();
    }
}
