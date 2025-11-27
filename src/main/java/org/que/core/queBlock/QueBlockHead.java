package org.que.core.queBlock;

import java.io.Serializable;

/**
 * 区块头（Block Head）
 * 只存储区块核心元信息，不存数据、不存签名
 */
public class QueBlockHead implements Serializable {

    public long blockNumber;    // 区块高度
    public long timestamp;      // 区块生成时间（ms）
    public String version;      // 区块版本号
    public String prevHash;     // 上一块 BlockHash

    public QueBlockHead() { }

    public QueBlockHead(long blockNumber, String version, String prevHash) {
        this.blockNumber = blockNumber;
        this.timestamp = System.currentTimeMillis();
        this.version = version;
        this.prevHash = prevHash;
    }

    @Override
    public String toString() {
        return "QueBlockHead{" +
                "blockNumber=" + blockNumber +
                ", timestamp=" + timestamp +
                ", version='" + version + '\'' +
                ", prevHash='" + prevHash + '\'' +
                '}';
    }
}

