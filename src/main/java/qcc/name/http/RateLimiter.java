package qcc.name.http;

import java.net.InetAddress;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 按来源 IP 的固定窗口限流（每分钟）。节点 IP 与回环地址不限流。
 * 写接口（register / unregister）每次要做 ML-DSA 验签并查 2~3 次链，必须限流，
 * 否则公网上很容易被刷到连带拖垮测试链节点。
 */
final class RateLimiter {

    private final int writePerMin, readPerMin;
    private final Set<InetAddress> exempt;
    private final ConcurrentHashMap<String, long[]> win = new ConcurrentHashMap<>();   // key → {windowStart, count}

    RateLimiter(int writePerMin, int readPerMin, Set<InetAddress> exempt) {
        this.writePerMin = writePerMin;
        this.readPerMin = readPerMin;
        this.exempt = Set.copyOf(exempt);
    }

    /** 允许返回 true；超限返回 false。 */
    boolean allow(InetAddress ip, boolean write) {
        if (ip.isLoopbackAddress() || exempt.contains(ip)) return true;
        long minute = System.currentTimeMillis() / 60_000;
        int limit = write ? writePerMin : readPerMin;
        long[] w = win.compute(ip.getHostAddress() + (write ? "|w" : "|r"), (k, v) -> {
            if (v == null || v[0] != minute) return new long[]{minute, 1};
            v[1]++;
            return v;
        });
        if (win.size() > 100_000) win.entrySet().removeIf(e -> e.getValue()[0] != minute);   // 防内存膨胀
        return w[1] <= limit;
    }
}
