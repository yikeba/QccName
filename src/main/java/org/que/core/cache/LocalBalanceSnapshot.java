package org.que.core.cache;

import org.que.core.queData.TransactionData;

import java.util.HashMap;
import java.util.Map;

public class LocalBalanceSnapshot {

    private final BalanceServer balanceServer;
    private final Map<String, Long> localBalance = new HashMap<>();

    public LocalBalanceSnapshot(BalanceServer balanceServer) {
        this.balanceServer = balanceServer;
    }

    public long getBalance(String address) {
        if (localBalance.containsKey(address)) {
            return localBalance.get(address);
        }
        long globalBalance = balanceServer.getBalance(address);
        localBalance.put(address, globalBalance);
        return globalBalance;
    }

    public long update(String address, long delta) {
        long oldVal = getBalance(address);   // 这里会先从 BalanceServer 读一次初始余额
        long newVal = oldVal + delta;
        localBalance.put(address, newVal);

        // ⭐⭐ 测试模式：顺带更新全网余额（MemoryBalanceServer）
        balanceServer.updateBalance(address, delta);

        return newVal;
    }


    // ✅ 通用增加/减少余额（仅改本地快照，不动全局）
  /*  public long update(String address, long delta) {
        long oldVal = getBalance(address);    // 自动从全局加载一次
        long newVal = oldVal + delta;
        localBalance.put(address, newVal);
        return newVal;
    }*/

    // 保留原来的快捷方法（可选）
    public boolean applyTransaction(TransactionData tx) {
        long fromBalance = getBalance(tx.from);

        if (fromBalance < tx.amount) {
            System.err.println("[LocalBalanceSnapshot] 余额不足: "
                    + tx.from + " 需要=" + tx.amount + " 实际=" + fromBalance);
            return false;
        }

        update(tx.from, -tx.amount);
        update(tx.to,   +tx.amount);

        return true;
    }

    public Map<String, Long> getSnapshot() {
        return localBalance;
    }

    public boolean containsAddress(String address) {
        return localBalance.containsKey(address);
    }

    @Override
    public String toString() {
        return "LocalBalanceSnapshot{size=" + localBalance.size() + "}";
    }
}
