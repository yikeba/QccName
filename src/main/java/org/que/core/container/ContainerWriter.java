package org.que.core.container;
import org.que.core.queBlock.QueBaseBlock;
import org.que.core.quecontainer.QueBaseContainer;
import org.que.core.quecontainer.QueContainerHead;
import org.que.core.quecontainer.QueContainerIndexEntry;
import org.que.crypto.CryptoUtil;

import java.io.File;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 容器写入类（QueContainerWriter）
 *
 * 负责把多个区块写入一个容器文件，并生成：
 *   1. Head（容器头）
 *   2. IndexList（偏移 + 长度 + 区块hash + bloom）
 *   3. Body（区块数据）
 *   4. Tail（SHA3-256 校验）
 *
 * 容器格式：
 * [ JSON(Head) ]
 * [ JSON(IndexList) ]
 * [ Block0 ]
 * [ Block1 ]
 * [ ... ]
 * [ SHA3 Tail ]
 */
public class ContainerWriter {

    /**
     * 写一个容器
     *
     * @param containerHead  容器头
     * @param blockList      区块列表（按顺序）
     * @param containerFile  要写入的容器文件
     */
    public static QueBaseContainer writeContainer(
            QueContainerHead containerHead,
            List<QueBaseBlock> blockList,
            File containerFile
    ) throws Exception {

        List<QueContainerIndexEntry> indexList = new ArrayList<>();

        // 1. ----------- 开始写文件 -----------
        FileOutputStream fos = new FileOutputStream(containerFile);

        // A. 写 Head（JSON 文本）
        byte[] headBytes = containerHead.toString().getBytes(StandardCharsets.UTF_8);
        fos.write(headBytes);

        // 换行符区分
        fos.write("\n".getBytes());

        long offset = headBytes.length + 1; // 下一段的起点

        // B. 写 IndexList 占位（先不写内容） → 以后回填
        long indexStart = offset;
        fos.write("INDEX_PLACEHOLDER\n".getBytes());
        offset += "INDEX_PLACEHOLDER\n".length();

        // C. 写 Block 区块数据
        for (int i = 0; i < blockList.size(); i++) {
            QueBaseBlock block = blockList.get(i);

            // 区块序列化（JSON）
            byte[] blockBytes = block.toString().getBytes(StandardCharsets.UTF_8);
            long blockOffset = offset;
            long blockLength = blockBytes.length;

            // 写区块数据
            fos.write(blockBytes);
            offset += blockLength;

            // 计算 bloom（用于地址查询）
            String bloom = buildSimpleBloom(block);

            // 区块索引项
            QueContainerIndexEntry entry = new QueContainerIndexEntry(
                    i,
                    block.head.blockNumber,   // 区块高度
                    block.foot.blockHash,     // 区块哈希（SHA3）
                    blockOffset,
                    blockLength,
                    bloom
            );

            indexList.add(entry);
        }

        // ----------- 写 Tail SHA3 校验 -----------
        fos.flush();
        fos.close();

        // 计算整个容器文件的 SHA3-256
        RandomAccessFile raf = new RandomAccessFile(containerFile, "r");
        byte[] fullBytes = new byte[(int) raf.length()];
        raf.readFully(fullBytes);
        raf.close();

        String tailHash = CryptoUtil.sha3256Hex(fullBytes);

        // 写入尾部 hash
        fos = new FileOutputStream(containerFile, true);
        fos.write(("\n" + tailHash).getBytes());
        fos.close();

        // ----------- 回填 IndexList -----------
        String indexJson = indexList.toString(); // 简单序列化
        byte[] indexBytes = indexJson.getBytes(StandardCharsets.UTF_8);

        raf = new RandomAccessFile(containerFile, "rw");
        raf.seek(indexStart);
        raf.write(indexBytes);
        raf.close();

        // ----------- 更新容器对象返回 -----------
        return new QueBaseContainer(containerHead, indexList, tailHash);
    }

    /**
     * 构建简单 Bloom Filter（地址前缀）
     */
    private static String buildSimpleBloom(QueBaseBlock block) {
        StringBuilder sb = new StringBuilder();

        block.body.dataList.forEach(data -> {
            // 抽取所有地址字段
            String addr = extractAddress(data.toString());
            if (addr != null) {
                sb.append(addr.substring(0, 4)).append("|");
            }
        });

        return sb.toString();
    }

    private static String extractAddress(String text) {
        int idx = text.indexOf("Q");
        if (idx == -1) return null;

        // 找到 Qxxxx 地址
        StringBuilder sb = new StringBuilder();
        for (int i = idx; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isLetterOrDigit(c)) {
                sb.append(c);
            } else break;
        }

        return sb.toString();
    }
}
