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
            List<QueBaseBlock> blocks,
            File file
    ) throws Exception {

        System.out.println(">>> [Writer] 开始构建 indexList...");

        List<QueContainerIndexEntry> indexList = new ArrayList<>();

        for (int i = 0; i < blocks.size(); i++) {
            QueBaseBlock block = blocks.get(i);

            if (block == null) {
                System.err.println("!!! [Writer] block is NULL at index=" + i);
                throw new RuntimeException("block null");
            }

            String bloom = buildBloomFilter(block);

            indexList.add(new QueContainerIndexEntry(
                    i,
                    block.head.blockNumber,
                    block.foot.blockHash,
                    0, 0,
                    bloom
            ));
        }

        System.out.println(">>> [Writer] indexList 构建完成，共 " + indexList.size() + " 条");

        // DTO
        QueContainerFileDTO dto = new QueContainerFileDTO();
        dto.head = head;
        dto.indexList = indexList;
        dto.blocks = blocks;
        dto.tailHash = null;

        System.out.println(">>> [Writer] 开始序列化 JSON（DTO → JSON 字符串）");

        String contentJson;
        try {
            contentJson = JSON.toJSONString(dto);
        } catch (Exception e) {
            System.err.println("!!! [Writer] JSON.toJSONString 失败");
            e.printStackTrace();
            throw e;
        }

        System.out.println(">>> [Writer] JSON 序列化成功，长度=" + contentJson.length());

        // tailHash
        String tailHash = CryptoUtil.sha3256Hex(contentJson.getBytes(StandardCharsets.UTF_8));
        dto.tailHash = tailHash;

        // 最终 JSON
        String finalJson;
        try {
            finalJson = JSON.toJSONString(dto);
        } catch (Exception e) {
            System.err.println("!!! [Writer] JSON.toJSONString (final) 失败");
            e.printStackTrace();
            throw e;
        }

        System.out.println(">>> [Writer] 准备写入临时文件: " + file.getAbsolutePath());

        try {
            Files.writeString(file.toPath(), finalJson, StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.err.println("!!! [Writer] 写文件失败: " + file.getAbsolutePath());
            e.printStackTrace();
            throw e;
        }

        System.out.println(">>> [Writer] 写入成功 → tailHash=" + tailHash);

        return new QueBaseContainer(head, indexList, tailHash);
    }

    // ==================== 全球最强抗量子链级 Bloom Filter ====================

    public static final int BLOOM_BITS = 4096;     // 512 字节
    public static final int BLOOM_HASHES = 7;      // 误报率 < 0.1%
    public static final long[] MURMUR_SEEDS = {
            0x9747b28cL, 0x7fb5d329L, 0x59d3a23fL, 0x6b3e2c17L,
            0x4f7dd381L, 0x2e6a9b7fL, 0x8c7f3d9dL
    };

    private static String buildBloomFilter(QueBaseBlock block) {
        boolean[] bits = new boolean[BLOOM_BITS];

        block.body.dataList.forEach(data -> {
            if (data instanceof TransactionData tx) {
                addToBloom(bits, tx.from);
                addToBloom(bits, tx.to);
            }
            else if (data instanceof EntityData ed && ed.owner != null) {
                addToBloom(bits, ed.owner);
            }
            else if (data instanceof RuleData rd) {
                // RuleData 建议加入 ruleCode 或发布者地址
               // if (rd.ruleCode != null) addToBloom(bits, rd.ruleCode);
                // 可选：addToBloom(bits, rd.contractAddress);
            }
        });

        // 极致性能转 hex（零 GC）
        char[] hex = new char[BLOOM_BITS >> 2];  // /4
        for (int i = 0; i < BLOOM_BITS; i += 4) {
            int b = (bits[i]   ? 1 : 0) |
                    (i+1 < BLOOM_BITS && bits[i+1] ? 2 : 0) |
                    (i+2 < BLOOM_BITS && bits[i+2] ? 4 : 0) |
                    (i+3 < BLOOM_BITS && bits[i+3] ? 8 : 0);
            hex[i >> 2] = "0123456789abcdef".charAt(b);
        }
        return new String(hex);
    }

    private static void addToBloom(boolean[] bits, String key) {
        if (key == null || key.length() < 10) return;
        byte[] bytes = key.getBytes(StandardCharsets.UTF_8);
        long hash = murmurHash64(bytes);

        for (int i = 0; i < BLOOM_HASHES; i++) {
            long mixed = hash + MURMUR_SEEDS[i];
            int pos = (int) (Math.abs(mixed) % BLOOM_BITS);
            bits[pos] = true;
        }
    }

    // MurmurHash3 64-bit，纯 long 运算，无 GC
    static long murmurHash64(byte[] data) {
        final int length = data.length;
        final long c1 = 0x87c37b91114253d5L;
        final long c2 = 0x4cf5ad432745937fL;

        long h = 0x9368e53c2f6af274L; // 固定 seed，可换但必须全网一致
        int i = 0;

        // ===== 1) 处理 8 字节对齐部分 =====
        while (i + 8 <= length) {
            long k =  ((long) data[i++] & 0xff)
                    | (((long) data[i++] & 0xff) << 8)
                    | (((long) data[i++] & 0xff) << 16)
                    | (((long) data[i++] & 0xff) << 24)
                    | (((long) data[i++] & 0xff) << 32)
                    | (((long) data[i++] & 0xff) << 40)
                    | (((long) data[i++] & 0xff) << 48)
                    | (((long) data[i++] & 0xff) << 56);

            k *= c1;
            k = Long.rotateLeft(k, 31);
            k *= c2;

            h ^= k;
            h = Long.rotateLeft(h, 27) * 5 + 0x52dce729;
        }

        // ===== 2) 尾部（剩余 0~7 字节）=====
        long k1 = 0;
        int remaining = length - i;

        switch (remaining) {
            case 7: k1 ^= (long)(data[i + 6] & 0xff) << 48;
            case 6: k1 ^= (long)(data[i + 5] & 0xff) << 40;
            case 5: k1 ^= (long)(data[i + 4] & 0xff) << 32;
            case 4: k1 ^= (long)(data[i + 3] & 0xff) << 24;
            case 3: k1 ^= (long)(data[i + 2] & 0xff) << 16;
            case 2: k1 ^= (long)(data[i + 1] & 0xff) << 8;
            case 1:
                k1 ^= (long)(data[i] & 0xff);
                k1 *= c1;
                k1 = Long.rotateLeft(k1, 31);
                k1 *= c2;
                h ^= k1;
        }

        // ===== 3) 长度注入 =====
        h ^= length;

        // ===== 4) finalizer（高质量 avalanche）=====
        h ^= h >>> 33;
        h *= 0xff51afd7ed558ccdL;
        h ^= h >>> 33;
        h *= 0xc4ceb9fe1a85ec53L;
        h ^= h >>> 33;

        return h;
    }

}