package org.que.core.quecontainer;
import java.io.Serializable;

/**
 * 容器头（QueContainerHead）
 *
 * 这是容器的核心元信息，用于共识、校验和快速同步。
 * 区块不会共识，容器才会共识。
 */
public class QueContainerHead implements Serializable {

    /** 容器ID（UUID或雪花算法）*/
    public String containerId;

    /** 容器所在合约地址（决定分片与并发）*/
    public String contractAddress;

    /** 容器高度（该合约下第 N 个容器）*/
    public long containerNumber;

    /** 上一个容器的哈希（同一合约链）*/
    public String prevContainerHash;

    /** 容器创建时间（毫秒时间戳）*/
    public long timestamp;

    /** 容器版本号（数据格式升级使用）*/
    public String version;

    /** 包含的区块数量 */
    public int blockCount;

    /** 容器原始未压缩大小（字节）*/
    public long rawSize;

    /** 容器压缩后的大小（字节）*/
    public long compressedSize;

    public QueContainerHead() {
    }

    public QueContainerHead(
            String containerId,
            String contractAddress,
            long containerNumber,
            String prevContainerHash,
            String version
    ) {
        this.containerId = containerId;
        this.contractAddress = contractAddress;
        this.containerNumber = containerNumber;
        this.prevContainerHash = prevContainerHash;
        this.version = version;
        this.timestamp = System.currentTimeMillis();
    }

    @Override
    public String toString() {
        return "QueContainerHead{" +
                "containerId='" + containerId + '\'' +
                ", contractAddress='" + contractAddress + '\'' +
                ", containerNumber=" + containerNumber +
                ", prevContainerHash='" + prevContainerHash + '\'' +
                ", timestamp=" + timestamp +
                ", version='" + version + '\'' +
                ", blockCount=" + blockCount +
                ", rawSize=" + rawSize +
                ", compressedSize=" + compressedSize +
                '}';
    }
}
