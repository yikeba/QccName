package org.que.core.cache;

// BalanceContext.java —— 极简、正确、永不为奴版
public final class BalanceContext {

    public static final MemoryBalanceServer BALANCE_SERVER = new MemoryBalanceServer();

    // 实时快照（出块用）
    public static final LocalBalanceSnapshot LIVE_SNAPSHOT = new LocalBalanceSnapshot(BALANCE_SERVER);

    // 回放快照（测试专用）—— 全局唯一实例
    private static LocalBalanceSnapshot REPLAY_SNAPSHOT = null;

    private BalanceContext() {}

    /** 测试专用：获取全局唯一的回放快照（只初始化一次） */
    public static synchronized LocalBalanceSnapshot getReplaySnapshot() {
        if (REPLAY_SNAPSHOT == null) {
            REPLAY_SNAPSHOT = new LocalBalanceSnapshot(BALANCE_SERVER, true); // 禁止懒加载
            System.out.println("[测试专用] 回放快照已创建（全局唯一）");
        }
        return REPLAY_SNAPSHOT;
    }

    /** 单元测试用：重置（可选） */
    public static synchronized void resetReplaySnapshot() {
        REPLAY_SNAPSHOT = null;
    }
}