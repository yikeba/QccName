package qcc.name.chain;

/**
 * 链查询失败（网络、服务端异常、响应结构不符）。必须与"查到了、但没有"区分开：
 * 前者返回 503 让客户端重试，后者才是"质押不满足"。
 * PledgeContext 失败时返回 {"ok":true,"data":"error"}，也归到这里。
 */
public class ChainUnavailableException extends RuntimeException {
    public ChainUnavailableException(String msg) { super(msg); }
    public ChainUnavailableException(String msg, Throwable cause) { super(msg, cause); }
}
