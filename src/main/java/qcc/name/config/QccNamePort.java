package qcc.name.config;

import java.util.Set;
import java.util.TreeSet;

/**
 * namespace 的端口分配,以及与 QCC 的冲突防护。
 *
 * QCC 已占用(来自 QccServicePort / QccnodeConfig):
 *   9080 HTTP    9333 P2P       9950 Hub      9952 index    9954 pool
 *   9443 HTTPS   9334 failover  9951 balance  9953 miner
 *
 * 光靠"约定错开"不够 —— 配置里少写一位就撞上去了,而绑定失败的报错
 * 往往指向别处。所以这里保留一张已占端口表,启动时命中就**拒绝启动**,
 * 并直接告诉运维撞的是哪个服务。
 */
public final class QccNamePort {

    /** 对外 HTTP。客户 API 与系统 API 都在这个口上,靠路径前缀区分。 */
    public static final int HTTP_PORT = Integer.getInteger("qccname.port", 9180);

    /** 内部管理与指标。只监听回环地址。 */
    public static final int ADMIN_PORT = Integer.getInteger("qccname.adminPort", 9181);

    /** QCC 同机部署时的本地 API 基址,用于 HttpChainView。 */
    public static final String QCC_BASE_URL =
            System.getProperty("qccname.qccBaseUrl", "http://127.0.0.1:9080");

    private static final Set<Integer> QCC_RESERVED = new TreeSet<>(Set.of(
            9080, 9443, 9333, 9334, 9950, 9951, 9952, 9953, 9954));

    private static final String[] QCC_NAMES = {
            "QCC HTTP", "QCC HTTPS", "QCC P2P", "QCC failover",
            "QCC Hub", "QCC balance", "QCC index", "QCC miner", "QCC pool"};

    private QccNamePort() {}

    /** 启动时调用。撞上 QCC 端口就拒绝启动,不要等到绑定失败再猜。 */
    public static void assertNoConflict() {
        check(HTTP_PORT,  "qccname.port");
        check(ADMIN_PORT, "qccname.adminPort");
        if (HTTP_PORT == ADMIN_PORT)
            throw new IllegalStateException("HTTP 与 ADMIN 端口不能相同: " + HTTP_PORT);
    }

    /** 任意端口的冲突检查（节点端口来自 peers 配置时使用）。 */
    public static void assertNotQccPort(int port, String what) { check(port, what); }

    private static void check(int port, String prop) {
        if (!QCC_RESERVED.contains(port)) return;
        int idx = 0;
        for (Integer p : QCC_RESERVED) {
            if (p == port) break;
            idx++;
        }
        throw new IllegalStateException(
                "端口 " + port + " (" + prop + ") 与 " + QCC_NAMES[idx]
                + " 冲突 —— 拒绝启动。请用 -D" + prop + "=<其他端口> 指定");
    }
}
