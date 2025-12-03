package org.que.core.container;


import com.alibaba.fastjson2.JSON;
import org.que.config.QubePath;
import org.que.core.queBlock.QueBaseBlock;
import org.que.core.queData.EntityData;
import org.que.core.queData.RuleData;
import org.que.core.queData.TransactionData;
import org.que.core.quecontainer.QueBaseContainer;
import org.que.core.quecontainer.QueContainerIndexEntry;
import org.que.core.quecontainer.QueContainerReader;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ==============================================================
 *         QubeChain 全网粗颗粒地址索引引擎（主网级）
 * ==============================================================
 *
 * 功能：
 *  ✔ 记录 Address → 出现过的容器编号列表
 *  ✔ 容器完成后自动更新
 *  ✔ 内存缓存 + 磁盘持久化
 *  ✔ 节点重启自动恢复
 *  ✔ 高性能（百万级地址）
 *  ✔ 查询极快（O(1)）
 *
 * 数据结构：
 *  addressToContainersMap:
 *      key = 地址（from/to/owner）
 *      value = [containerNumber1, containerNumber2, ...]
 *
 * 存储路径：
 *  ~/.qubechain/cache/index/address_index.json
 *
 * ==============================================================
 */
public class ContainerIndexEngine {

    /** 内存级全网索引（线程安全） */
    private static final Map<String, List<Long>> ADDRESS_MAP = new ConcurrentHashMap<>();

    /** 磁盘持久化路径 */
    private static final Path INDEX_FILE =
            QubePath.CACHE_DIR.resolve("index/address_index.json");

    static {
        loadFromDisk();
    }

    // ==========================================================
    //  🔥 1. 主入口：容器完成后调用
    // ==========================================================
    public static void update(QueBaseContainer container) {
        if (container == null || container.indexList == null) return;

        long containerNumber = container.head.containerNumber;
        System.out.println(">>> [IndexEngine] 开始处理容器 #" + containerNumber);
        // 遍历所有区块
        for (QueContainerIndexEntry entry : container.indexList) {

            QueBaseBlock block = QueContainerReader.readBlock(
                    container.containerFilePath,
                    entry.offset,
                    entry.length
            );

            if (block == null) continue;

            List<String> addresses = extractAddressesFromBlock(block);

            for (String addr : addresses) {
                if (addr != null && addr.length() >= 10) {
                    ADDRESS_MAP.computeIfAbsent(addr, k -> new ArrayList<>())
                            .add(containerNumber);
                }
            }
        }


        saveToDisk();
        System.out.println(">>> [IndexEngine] 容器 #" + containerNumber + " 索引更新完成");
    }

    // ==========================================================
    //  🔥 2. 提供外部查询接口
    // ==========================================================
    public static List<Long> queryAddressContainers(String address) {
        return ADDRESS_MAP.getOrDefault(address, Collections.emptyList());
    }

    public static Map<String, List<Long>> getGlobalIndex() {
        return ADDRESS_MAP;
    }

    // ==========================================================
    //  🔥 3. 从 Block 提取所有地址
    // ==========================================================
    private static List<String> extractAddressesFromBlock(QueBaseBlock block) {
        List<String> list = new ArrayList<>();

        block.body.dataList.forEach(data -> {

            // =============================
            // TransactionData
            // =============================
            if (data instanceof TransactionData tx) {
                if (tx.from != null) list.add(tx.from);
                if (tx.to != null) list.add(tx.to);
            }

            // =============================
            // EntityData（实体数据：owner）
            // =============================
            else if (data instanceof EntityData ed) {
                if (ed.owner != null) list.add(ed.owner);
            }

            // =============================
            // RuleData（规则容器未来可能需要地址）
            // =============================
            else if (data instanceof RuleData rd) {
                // 如果未来规则记录涉及地址，这里加解析
                // list.add(rd.address);
            }
        });

        return list;
    }

    // ==========================================================
    //  🔥 4. 磁盘持久化（JSON）
    // ==========================================================
    private static synchronized void saveToDisk() {
        try {
            // 确保目录存在
            Files.createDirectories(INDEX_FILE.getParent());

            String json = JSON.toJSONString(ADDRESS_MAP);

            Files.writeString(INDEX_FILE, json, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING);

        } catch (IOException e) {
            System.err.println(">>> [IndexEngine] 写入索引失败");
            e.printStackTrace();
        }
    }

    // ==========================================================
    //  🔥 5. 从磁盘恢复内存 index
    // ==========================================================
    private static void loadFromDisk() {
        try {
            if (!Files.exists(INDEX_FILE)) {
                Files.createDirectories(INDEX_FILE.getParent());
                return;
            }

            String json = Files.readString(INDEX_FILE, StandardCharsets.UTF_8);
            if (json == null || json.isEmpty()) return;

            Map<String, List<Long>> map = JSON.parseObject(json, Map.class);

            if (map != null) {
                ADDRESS_MAP.putAll(map);
            }

            System.out.println(">>> [IndexEngine] 加载索引成功，地址数量="
                    + ADDRESS_MAP.size());

        } catch (Exception e) {
            System.err.println(">>> [IndexEngine] 加载索引失败");
            e.printStackTrace();
        }
    }
}
