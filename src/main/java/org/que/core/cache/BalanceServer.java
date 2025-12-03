package org.que.core.cache;

/**
 * 全网余额服务接口
 *
 * 说明：
 * - getBalance：读取当前已确认的真实余额
 * - updateBalance：对余额做“增量修改”（delta），不是直接覆盖
 * - initBalance：用于测试/创世初始化，直接设置某地址余额
 */
public interface BalanceServer {
    /**
     * 获取某地址当前全网真实余额
     */
    long getBalance(String address);

    /**
     * 增量更新余额（专业版语义：delta）
     *
     * @param address 地址
     * @param delta   余额变化值（可以为正/负）
     *                例如：+100 / -50
     */
    void updateBalance(String address, long delta);

    /**
     * 初始化某地址余额（用于创世 / 测试）
     * 这是“覆盖语义”，与 updateBalance 的“增量语义”区分开。
     */
    void initBalance(String address, long balance);
}
