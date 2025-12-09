package org.que.service;

import org.que.core.queBlock.QueBaseBlock;
import org.que.core.quecontainer.QueBaseContainer;
import org.que.core.queData.QueBaseData;
import org.que.core.queData.TransactionData;

import java.util.ArrayList;
import java.util.List;
// 假设 containersCache 已经通过 init() 方法加载了所有容器

public class QubeQueryService {

    // 假设：全局容器列表缓存 (由 init() 初始化)
    private static List<QueBaseContainer> containersCache = new ArrayList<>();
    // ... init() 方法需要实现 ...

    /**
     * 2. 交易明细查询 API (Transaction History/Detail API)
     * 利用 Bloom Filter 筛选容器，然后遍历区块数据
     */
    public static List<TransactionData> getTransactionsByAddress(String address) {
        if (address == null || address.isEmpty()) return new ArrayList<>();

        List<TransactionData> results = new ArrayList<>();

        // 遍历所有已加载的容器
        for (QueBaseContainer container : containersCache) {

            // 使用 Bloom Filter 快速判断容器内是否有该地址的活动
            if (container.findBlocksByAddress(address).isEmpty()) {
                continue; // 容器内一定没有，跳过整个容器的加载和遍历
            }

            // Bloom Filter 命中，现在进行精确查询
            if (container.blocks == null) continue;

            for (QueBaseBlock block : container.blocks) {
                if (block.body == null || block.body.dataList == null) continue;

                // 遍历区块内的所有数据项
                for (QueBaseData data : block.body.dataList) {
                    if (data instanceof TransactionData tx) {
                        // 匹配交易的 from 或 to 地址
                        if (address.equals(tx.from) || address.equals(tx.to)) {
                            results.add(tx);
                        }
                    }
                    // 如果未来有 EntityData / RuleData 变动，也可在此处捕获
                }
            }
        }
        return results;
    }
}