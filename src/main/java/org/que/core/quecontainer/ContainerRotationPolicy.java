package org.que.core.quecontainer;

import org.que.core.queBlock.QueBaseBlock;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 容器切割策略（单一职责）
 *
 * 负责：
 *  - 是否达到容器大小阈值
 *  - 是否达到区块数量阈值
 *  - 未来可扩展时间阈值、类型分容器
 */
public class ContainerRotationPolicy {

    // 容器区块数量阈值
    private static final int MAX_BLOCKS_PER_CONTAINER = 100;

    // 容器大小阈值（200MB）
    private static final long MAX_BYTES_PER_CONTAINER = 200L * 1024 * 1024;

    /**
     * 判断是否需要切割容器
     */
    public static boolean shouldFlush(List<QueBaseBlock> blocks) {
        if (blocks == null || blocks.isEmpty()) return false;

        // 条件一：区块数量
        if (blocks.size() >= MAX_BLOCKS_PER_CONTAINER) return true;

        // 条件二：容器体积
        long totalBytes = blocks.stream()
                .mapToLong(b -> b.toJson().getBytes(StandardCharsets.UTF_8).length)
                .sum();

        return totalBytes >= MAX_BYTES_PER_CONTAINER;
    }
}
