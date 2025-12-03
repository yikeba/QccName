package org.que.core.quecontainer;

import com.alibaba.fastjson2.JSON;
import org.que.config.QubePath;
import org.que.core.queBlock.QueBaseBlock;
import org.que.core.queData.EntityData;
import org.que.core.queData.RuleData;
import org.que.core.queData.TransactionData;
import org.que.crypto.CryptoUtil;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * JSON 容器写入类（测试网 → 主网就绪）
 * 包含全球最强抗量子链级 Bloom Filter（4096bit + 7-hash + Murmur64）
 */

public class QueContainerWriter {

    public static QueBaseContainer writeContainer(
            QueContainerHead head,
            List<QueContainerIndexEntry> indexList,
            List<QueBaseBlock> blocks,
            File file
    ) throws Exception {

        System.out.println(">>> [Writer] 使用已构建的 indexList, size=" + indexList.size());

        QueContainerFileDTO dto = new QueContainerFileDTO();
        dto.head = head;
        dto.indexList = indexList;
        dto.blocks = blocks;
        dto.tailHash = null;

        System.out.println(">>> [Writer] 开始序列化 JSON（DTO → JSON 字符串）");

        String contentJson = com.alibaba.fastjson2.JSON.toJSONString(dto);

        System.out.println(">>> [Writer] JSON 序列化成功，长度=" + contentJson.length());

        String tailHash = org.que.crypto.CryptoUtil.sha3256Hex(
                contentJson.getBytes(StandardCharsets.UTF_8)
        );
        dto.tailHash = tailHash;

        String finalJson = com.alibaba.fastjson2.JSON.toJSONString(dto);

        System.out.println(">>> [Writer] 准备写入临时文件: " + file.getAbsolutePath());

        java.nio.file.Files.writeString(file.toPath(), finalJson, java.nio.charset.StandardCharsets.UTF_8);

        System.out.println(">>> [Writer] 写入成功 → tailHash=" + tailHash);

        return new QueBaseContainer(head, indexList, tailHash);
    }

    // BloomFilter 相关代码已经迁移到 BloomFilterUtil
}
