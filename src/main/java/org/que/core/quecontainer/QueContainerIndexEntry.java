package org.que.core.quecontainer;

import java.io.Serializable;

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
    public boolean containsAddress(String address) {
        if (bloomFilter == null || address == null) return false;

        // 简单方案：Bloom Filter 字符串包含地址特征（例如前4字符）
        String key = address.substring(0, Math.min(address.length(), 6)); // 取前 6 位增强唯一性

        return bloomFilter.contains(key);
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
