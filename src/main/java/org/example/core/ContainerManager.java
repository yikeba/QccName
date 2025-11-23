// ContainerManager.java —— 唯一有脑子的类（3分钟、10MB、共识、广播全在这）
package org.example.core;

import org.example.config.QubePath;

import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class ContainerManager {

    private static final ContainerManager INSTANCE = new ContainerManager();

    private static final long MAX_LIFETIME_MS = 3 * 60 * 1000L;     // 3分钟硬超时
    private static final long MAX_SIZE_BYTES = 10L * 1024 * 1024;  // 10MB硬限
    private static final long EMPTY_TIMEOUT_MS = 60 * 1000L;       // 空容器60秒强制结束

    private volatile Container currentContainer;
    private long containerStartTime;

    private ContainerManager() {
        QubePath.init();
        startNewContainer();
        startLifecycleMonitor();
        System.out.println("【量子容器管理器就位】3分钟 + 10MB 双硬限，全球最硬生产逻辑");
    }

    public static ContainerManager getInstance() { return INSTANCE; }

    // 对外唯一写入入口
    public void submitBlock(Block sealedBlock) {
        Container c = currentContainer;
        if (c == null) return;

        // 容量检查
        if (c.getFileSize() >= MAX_SIZE_BYTES) {
            System.out.println("【10MB硬限触发】等待下一容器");
            return;
        }

        c.appendBlock(sealedBlock);
    }

    // 强制触发密封（由定时器或外部共识调用）
    private synchronized void sealCurrentContainer() {
        Container c = currentContainer;
        if (c == null) return;

        System.out.println("【强制密封】容器 " + c.containerId + " 结束生命周期");
        c.sealAndClose();

        // TODO: 触发P2P共识 + 广播完整容器文件
        broadcastContainer(c);

        c.archive();

        startNewContainer();
    }

    private void broadcastContainer(Container c) {
        System.out.println("【P2P广播】开始广播完整容器文件，大小=" + c.getFileSize()/1024.0/1024 + "MB");
        // TODO: 分片广播 + 索引服务器推送
    }

    private void startNewContainer() {
        currentContainer = new Container();
        containerStartTime = System.currentTimeMillis();
        System.out.println("【新容器启动】ID=" + currentContainer.containerId + "，开始接收区块");
    }

    // 生命周期监控（每秒检查）
    private void startLifecycleMonitor() {
        Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(() -> {
            Container c = currentContainer;
            if (c == null) return;

            long age = System.currentTimeMillis() - containerStartTime;
            long size = c.getFileSize();

            if (age >= MAX_LIFETIME_MS) {
                System.out.println("【3分钟硬超时】强制密封");
                sealCurrentContainer();
            } else if (size >= MAX_SIZE_BYTES) {
                System.out.println("【10MB硬限】强制密封");
                sealCurrentContainer();
            } else if (c.getBlockCount() == 0 && age > EMPTY_TIMEOUT_MS) {
                System.out.println("【空容器超时】强制密封");
                sealCurrentContainer();
            }
        }, 1, 1, TimeUnit.SECONDS);
    }

    public Container getCurrentContainer() { return currentContainer; }
}