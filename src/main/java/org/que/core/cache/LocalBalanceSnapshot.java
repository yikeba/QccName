// LocalBalanceSnapshot.java  —— 只需要改这一个文件
package org.que.core.cache;

import org.que.core.queData.TransactionData;

import java.util.HashMap;
import java.util.Map;

public class LocalBalanceSnapshot {

    private final BalanceServer balanceServer;
    private final Map<String, Long> localBalance = new HashMap<>();

    // 新增：回放模式开关（关键！）
    private final boolean replayMode;

    // 保留你原来的构造器（实时模式）
    public LocalBalanceSnapshot(BalanceServer balanceServer) {
        this(balanceServer, false);  // 默认不是回放模式
    }

    // 新增：支持指定是否为回放模式
    public LocalBalanceSnapshot(BalanceServer balanceServer, boolean replayMode) {
        this.balanceServer = balanceServer;
        this.replayMode = replayMode;
    }

    public long getBalance(String address) {
        if (address == null) return 0L;

        // 如果已经在本地快照里，直接返回
        if (localBalance.containsKey(address)) {
            return localBalance.get(address);
        }

        // 关键修复：回放模式下，绝不读取全局！初始余额必须为 0
        if (replayMode) {
            //localBalance.put(address, 0L);  // 强制初始化为 0
            return 0L;
        }

        // 实时模式才去全局查（懒加载）
        long global = balanceServer.getBalance(address);
        localBalance.put(address, global);
        return global;
    }

    public long update(String address, long delta) {
        long current = getBalance(address);  // 现在安全了
        long newVal = current + delta;
        localBalance.put(address, newVal);
        return newVal;
    }

    // 保留你原来的 applyTransaction，完全不动
    public boolean applyTransaction(TransactionData tx) {
        long fromBalance = getBalance(tx.from);
        if (fromBalance < tx.amount) {
            System.err.println("[回放失败] 余额不足: " + tx.from +
                    " 需要=" + tx.amount + " 实际=" + fromBalance);
            return false;
        }
        update(tx.from, -tx.amount);
        update(tx.to,   +tx.amount);
        return true;
    }

    public Map<String, Long> getSnapshot() {
        return new HashMap<>(localBalance);  // 返回副本更安全
    }

    @Override
    public String toString() {
        return "LocalBalanceSnapshot{replay=" + replayMode + ", size=" + localBalance.size() + "}";
    }
}