package org.que.core.quecontainer;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;

/**
 * 容器区块索引项（含查询优化）
 *
 * 用于快速定位区块位置，并判断该区块是否有某地址相关数据。
 */
public class QueContainerIndexEntry implements Serializable {

    /** 区块在容器中的顺序编号（0~N） */
    public int blockIndex;

    /** 区块在本合约链中的高度（blockNumber） */
    public long blockNumber;

    /** 区块 SHA3-256 哈希（校验用） */
    public String blockHash;

    /** 区块在容器文件中的偏移位置 */
    public long offset;

    /** 区块的字节长度 */
    public long length;

    /**
     * 地址查询 Bloom Filter
     * 可以是 bitset 字符串、多个 hash 拼接、或简单字符串
     */
    public String bloomFilter;

    public QueContainerIndexEntry() {}

    public QueContainerIndexEntry(
            int blockIndex,
            long blockNumber,
            String blockHash,
            long offset,
            long length,
            String bloomFilter) {

        this.blockIndex = blockIndex;
        this.blockNumber = blockNumber;
        this.blockHash = blockHash;
        this.offset = offset;
        this.length = length;
        this.bloomFilter = bloomFilter;
    }

    /**
     * 查询增强：判断此区块是否“可能”包含该地址的数据。
     * （Bloom Filter 原理：可能包含 / 一定不包含）
     */
  /*  public boolean containsAddress(String address) {
        if (bloomFilter == null || address == null || address.length() < 10) return false;

        long hash = QueContainerWriter.murmurHash64(address.getBytes(StandardCharsets.UTF_8));
        for (int i = 0; i < QueContainerWriter.BLOOM_HASHES; i++) {
            long mixed = hash + QueContainerWriter.MURMUR_SEEDS[i];
            int pos = (int) (Math.abs(mixed) % QueContainerWriter.BLOOM_BITS);
            int hexIdx = pos >> 2;
            int bitIdx = pos & 3;
            if (hexIdx >= bloomFilter.length()) return false;
            int hexVal = Character.digit(bloomFilter.charAt(hexIdx), 16);
            if (hexVal < 0 || (hexVal & (1 << bitIdx)) == 0) {
                return false;
            }
        }
        return true;
    }*/
    public boolean containsAddress(String address) {
        if (bloomFilter == null || address == null || address.length() < 10) return false;

        long hash = BloomFilterUtil.murmurHash64(address.getBytes(StandardCharsets.UTF_8));
        for (int i = 0; i < BloomFilterUtil.BLOOM_HASHES; i++) {
            long mixed = hash + BloomFilterUtil.MURMUR_SEEDS[i];
            int pos = (int) (Math.abs(mixed) % BloomFilterUtil.BLOOM_BITS);
            int hexIdx = pos >> 2;
            int bitIdx = pos & 3;
            if (hexIdx >= bloomFilter.length()) return false;
            int hexVal = Character.digit(bloomFilter.charAt(hexIdx), 16);
            if (hexVal < 0 || (hexVal & (1 << bitIdx)) == 0) {
                return false;
            }
        }
        return true;
    }


    @Override
    public String toString() {
        return "QueContainerIndexEntry{" +
                "blockIndex=" + blockIndex +
                ", blockNumber=" + blockNumber +
                ", blockHash='" + blockHash + '\'' +
                ", offset=" + offset +
                ", length=" + length +
                ", bloomFilter='" + bloomFilter + '\'' +
                '}';
    }
}
