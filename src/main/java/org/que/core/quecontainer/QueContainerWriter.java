package org.que.core.quecontainer;

import com.alibaba.fastjson2.JSON;
import org.que.core.queBlock.QueBaseBlock;
import org.que.crypto.CryptoUtil;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * JSON 容器写入类（测试网）
 *
 * 写出的容器结构为：
 * {
 *   "head": {...},
 *   "indexList": [...],
 *   "blocks": [...],
 *   "tailHash": "sha3-256"
 * }
 */
public class QueContainerWriter {

    public static QueBaseContainer writeContainer(
            QueContainerHead head,
            List<QueBaseBlock> blocks,
            File file
    ) throws Exception {

        // -----------------------------
        // 1) 构建 indexList（只负责元数据）
        // -----------------------------
        List<QueContainerIndexEntry> indexList = new ArrayList<>();

        for (int i = 0; i < blocks.size(); i++) {
            QueBaseBlock block = blocks.get(i);

            String bloom = buildSimpleBloom(block);

            QueContainerIndexEntry entry = new QueContainerIndexEntry(
                    i,
                    block.head.blockNumber,
                    block.foot.blockHash,
                    0,       // JSON 版本 offset 不需要
                    0,       // JSON 版本 length 不需要
                    bloom
            );

            indexList.add(entry);
        }

        // -----------------------------
        // 2) 构建 DTO
        // -----------------------------
        QueContainerFileDTO dto = new QueContainerFileDTO();
        dto.head = head;
        dto.indexList = indexList;
        dto.blocks = blocks;
        dto.tailHash = null;   // 等下计算

        // -----------------------------
        // 3) 计算 tailHash
        // -----------------------------
        String contentJson = JSON.toJSONString(dto);
        String tailHash = CryptoUtil.sha3256Hex(contentJson.getBytes(StandardCharsets.UTF_8));

        dto.tailHash = tailHash;

        // -----------------------------
        // 4) 最终写入文件
        // -----------------------------
        String finalJson = JSON.toJSONString(dto);
        Files.writeString(file.toPath(), finalJson, StandardCharsets.UTF_8);

        // 返回容器对象
        return new QueBaseContainer(head, indexList, tailHash);
    }

    /**
     * 构建简单 bloom
     */
    private static String buildSimpleBloom(QueBaseBlock block) {
        StringBuilder sb = new StringBuilder();

        block.body.dataList.forEach(data -> {
            String text = data.toString();
            int idx = text.indexOf("Q");
            if (idx != -1) {
                // 取 Q 开头的地址前 5 位
                String prefix = text.substring(idx, Math.min(idx + 6, text.length()));
                sb.append(prefix).append("|");
            }
        });

        return sb.toString();
    }
}
