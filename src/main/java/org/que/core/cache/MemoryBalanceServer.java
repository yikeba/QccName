package org.que.core.cache;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 内存版余额服务器：
 * - 线程安全
 * - 适合本地测试 / 单节点开发
 * - 后期可以无缝替换为 Redis/MySQL/集群实现
 */
public class MemoryBalanceServer implements BalanceServer {

    private final Map<String, Long> balanceMap = new ConcurrentHashMap<>();

    @Override
    public long getBalance(String address) {
        if (address == null) return 0L;
        return balanceMap.getOrDefault(address, 0L);
    }

    // MemoryBalanceServer.java
    public Map<String, Long> getAllBalancesCopy() {
        return Map.copyOf(balanceMap);  // Java 10+ 不可变副本，线程安全
    }

    @Override
    public void updateBalance(String address, long delta) {
        if (address == null || delta == 0L) return;

        balanceMap.merge(address, delta, Long::sum);
    }

    @Override
    public void initBalance(String address, long balance) {
        if (address == null) return;
        balanceMap.put(address, balance);
    }

    @Override
    public String toString() {
        return "MemoryBalanceServer{size=" + balanceMap.size() + "}";
    }
}
