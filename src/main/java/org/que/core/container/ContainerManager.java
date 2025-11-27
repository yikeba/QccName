package org.que.core.container;

import org.que.config.QubePath;
import org.que.core.block.QubeBlock;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;

/**
 * ContainerManager —— 容器生命周期与调度中心（OS Kernel）
 *
 * 负责：
 *  - 容器创建/切换/封存/销毁
 *  - 多容器并发安全
 *  - 合约地址 → 活跃容器 的路由
 *  - 自动 3 分钟 / 200MB 容器切换
 */
public final class ContainerManager {

    // ===================== 单例模式 =====================

    private static final ContainerManager INSTANCE = new ContainerManager();
    public static ContainerManager getInstance() { return INSTANCE; }

    // ===================== 成员字段 =====================

    /** Map: contractAddressHex → QubeContainer（活跃容器） */
    private final ConcurrentHashMap<String, QubeContainer> activeContainers = new ConcurrentHashMap<>();

    /** 全局线程池（定时检查容器状态） */
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    /** 管理器状态 */
    private volatile boolean running = false;

    // ===================== 启动管理器 =====================

    private ContainerManager() {
        // 私有构造器
    }

    public synchronized void start() {
        if (running) return;
        running = true;

        // 每 10 秒扫描容器状态
        scheduler.scheduleAtFixedRate(this::scanActiveContainers,
                10, 10, TimeUnit.SECONDS);
    }

    public synchronized void stop() {
        running = false;
        scheduler.shutdown();
    }

    // ===================== 获取或创建容器 =====================

    public QubeContainer getOrCreateContainer(byte[] contractAddress) {
        String hex = toHex(contractAddress);

        // 已有容器？返回
        QubeContainer c = activeContainers.get(hex);
        if (c != null && !c.isSealed()) {
            return c;
        }

        synchronized (hex.intern()) {
            // 双重检查
            c = activeContainers.get(hex);
            if (c != null && !c.isSealed()) {
                return c;
            }

            try {
                QubeContainer newContainer = QubeContainer.createNewForContract(contractAddress);
                activeContainers.put(hex, newContainer);
                System.out.println("[CM] Created new container: " + newContainer);
                return newContainer;
            } catch (IOException e) {
                throw new RuntimeException("创建容器失败：" + e.getMessage(), e);
            }
        }
    }

    // ===================== 写入记录（对上层暴露） =====================

    public void appendBlockToContract(byte[] contractAddress, QubeBlock block, byte[] blockBytes) {
        QubeContainer container = getOrCreateContainer(contractAddress);

        synchronized (container) {
            container.appendBlock(block, blockBytes);

            // 是否需要自动封存
            if (shouldSeal(container)) {
                sealAndSwitch(container, contractAddress);
            }
        }
    }

    // ===================== 容器扫描（3分钟/200MB）=====================

    private void scanActiveContainers() {
        long now = System.currentTimeMillis();

        for (Map.Entry<String, QubeContainer> e : activeContainers.entrySet()) {
            QubeContainer c = e.getValue();

            synchronized (c) {
                // 1. 空容器超过 3 分钟 → 删除
                if (c.isEmpty() && (now - c.getCreateTimeMillis() > QubeContainer.DEFAULT_MAX_LIFETIME_MS)) {
                    deleteContainer(c, e.getKey());
                    continue;
                }

                // 2. 非空容器达到阈值 → 封存
                if (shouldSeal(c)) {
                    sealAndSwitch(c, hexToBytes(e.getKey()));
                }
            }
        }
    }

    // ===================== 封存 + 切换新容器 =====================

    private void sealAndSwitch(QubeContainer c, byte[] contractAddress) {
        try {
            c.seal();
            c.close();

            // 移动到 DATA_DIR（归档）
            Path newPath = QubePath.DATA_DIR.resolve(c.toString() + ".sealed");
            Files.move(c.path, newPath);

            System.out.println("[CM] Container sealed and archived: " + newPath);

            // 为该合约创建新容器
            String hex = toHex(contractAddress);
            QubeContainer newContainer = QubeContainer.createNewForContract(contractAddress);
            activeContainers.put(hex, newContainer);

        } catch (Exception e) {
            throw new RuntimeException("容器封存失败：" + e.getMessage(), e);
        }
    }

    // ===================== 删除空容器 =====================

    private void deleteContainer(QubeContainer c, String contractHex) {
        try {
            System.out.println("[CM] Empty container expired, deleting: " + c);
            Files.deleteIfExists(c.path);
        } catch (Exception ignored) {}

        activeContainers.remove(contractHex);
    }

    // ===================== 规则判断 =====================

    private boolean shouldSeal(QubeContainer c) {
        long now = System.currentTimeMillis();
        long age = now - c.getCreateTimeMillis();
        long size = c.getCurrentSize();

        return (age >= QubeContainer.DEFAULT_MAX_LIFETIME_MS)
                || (size >= QubeContainer.DEFAULT_MAX_SIZE_BYTES);
    }

    // ===================== 工具函数 =====================

    private static String toHex(byte[] arr) {
        StringBuilder sb = new StringBuilder(arr.length * 2);
        for (byte b : arr) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] arr = new byte[len / 2];
        for (int i = 0; i < arr.length; i++) {
            arr[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return arr;
    }
}

