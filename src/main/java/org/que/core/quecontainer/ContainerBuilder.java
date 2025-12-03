package org.que.core.quecontainer;

import org.que.core.queBlock.QueBaseBlock;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 容器构建器：
 * - 负责根据 blocks 构建 QueContainerHead + indexList
 * - 统计 rawSize
 * - 将来可以在这里做压缩、分片等预处理
 */
public class ContainerBuilder {

    public static class BuildResult {
        public final QueContainerHead head;
        public final List<QueContainerIndexEntry> indexList;
        public final long rawSize;

        public BuildResult(QueContainerHead head,
                           List<QueContainerIndexEntry> indexList,
                           long rawSize) {
            this.head = head;
            this.indexList = indexList;
            this.rawSize = rawSize;
        }
    }

    public static BuildResult build(
            String contractAddress,
            long containerNumber,
            String prevContainerHash,
            List<QueBaseBlock> blocks
    ) {
        if (blocks == null || blocks.isEmpty()) {
            throw new IllegalArgumentException("blocks 不能为空");
        }

        QueContainerHead head = new QueContainerHead(
                java.util.UUID.randomUUID().toString().replace("-", ""),
                contractAddress,
                containerNumber,
                prevContainerHash,
                "1.0.0"
        );

        List<QueContainerIndexEntry> indexList = new ArrayList<>();
        long rawSize = 0L;

        for (int i = 0; i < blocks.size(); i++) {
            QueBaseBlock block = blocks.get(i);
            if (block == null) {
                throw new RuntimeException("block is null at index=" + i);
            }

            String json = block.toJson();
            rawSize += json.getBytes(StandardCharsets.UTF_8).length;

            String bloom = BloomFilterUtil.buildBloomFilter(block);

            QueContainerIndexEntry entry = new QueContainerIndexEntry(
                    i,
                    block.head.blockNumber,
                    block.foot.blockHash,
                    0, 0,          // JSON 模式下 offset/length 暂时为 0
                    bloom
            );
            indexList.add(entry);
        }

        head.blockCount = blocks.size();
        head.rawSize = rawSize;
        head.compressedSize = rawSize; // 将来支持压缩时再修改

        return new BuildResult(head, indexList, rawSize);
    }
}

