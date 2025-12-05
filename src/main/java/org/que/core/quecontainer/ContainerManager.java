package org.que.core.quecontainer;

import org.que.core.container.ContainerEvent;
import org.que.core.container.ContainerEventManager;
import org.que.core.container.ContainerEventType;
import org.que.core.queBlock.QueBaseBlock;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 容器管理器：
 * - 接受区块（BlockController.appendBlock 调用）
 * - 按策略聚合为容器（数量/体积）
 * - 调用 ContainerWriter 真正落盘
 */
public class ContainerManager {

    // 容器切换策略（先用简单版本，后面可用 ContainerRotationPolicy 抽象）
    private static final int MAX_BLOCKS_PER_CONTAINER = 100;           // 主网可以调到 500~2000
    private static final long MAX_BYTES_PER_CONTAINER = 200L * 1024 * 1024; // 200MB

    private static final List<QueBaseBlock> currentBlocks = new ArrayList<>();
    private static final AtomicLong containerSeq = new AtomicLong(1);

    // 创世容器前哈希
    private static String prevContainerHash =
            "0000000000000000000000000000000000000000000000000000000000000000";

    private static volatile boolean isClosed = false;

    static {
        // JVM 退出时保证最后一批容器刷盘
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("JVM 关闭中，触发 ContainerManager.close()...");
            ContainerManager.close();
        }));
    }

    /**
     * 接收新区块（由 BlockController 调用）
     */
    public static synchronized void appendBlock(QueBaseBlock block) {
        if (isClosed) {
            throw new IllegalStateException("ContainerManager 已关闭，无法接收新区块");
        }
        //System.out.println("[Writer] 实际写入容器路径 = " + filePath);
        currentBlocks.add(block);

        if (shouldFlush()) {
            flushContainer();
        }
    }

    private static boolean shouldFlush() {
        return ContainerRotationPolicy.shouldFlush(currentBlocks);
    }

    /**
     * 外部强制刷盘（比如测试完/节点停机前）
     */
    public static synchronized void flush() {
        if (!currentBlocks.isEmpty()) {
            flushContainer();
        }
    }


    /**
     * 关闭管理器：先刷盘，再标记关闭
     */
    public static synchronized void close() {
        if (isClosed) return;
        flush();
        isClosed = true;
        System.out.println("ContainerManager 已安全关闭，所有容器已刷盘。");
    }

    /**
     * 核心：把 currentBlocks 聚合成一个容器并写入磁盘
     */
    private static void flushContainer() {
        if (currentBlocks.isEmpty()) return;

        long containerNumber = containerSeq.getAndIncrement();
        QueBaseContainer container = ContainerWriter.writeContainer(
                containerNumber,
                prevContainerHash,
                new ArrayList<>(currentBlocks)   // 防止引用被修改
        );
        prevContainerHash = container.tailHash;
        System.out.println(
                "容器写入成功 #" + containerNumber +
                        " 区块数=" + currentBlocks.size() +
                        " tailHash=" + container.tailHash.substring(0, 16) + "..."
        );
        // 容器完成生命周期事件
        ContainerEventManager.trigger(
                new ContainerEvent(ContainerEventType.CONTAINER_FINALIZED, container)
        );
        currentBlocks.clear();
    }

    // ====== 调试用接口 ======
    public static long getCurrentContainerSeq() {
        return containerSeq.get();
    }

    public static int getPendingBlockCount() {
        return currentBlocks.size();
    }

    public static String getPrevContainerHash() {
        return prevContainerHash;
    }
}
