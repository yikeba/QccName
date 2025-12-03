package org.que.core.container;


public enum ContainerEventType {
    CONTAINER_FINALIZED,   // 容器写入成功（主事件）
    INDEX_GENERATED,       // 若有单独索引构建阶段，可以用
    BALANCE_REBUILT,       // 余额重算
    CONTAINER_BROADCAST,   // 广播给其他节点
    COLD_FLUSHED           // 热 -> 冷存储
}
