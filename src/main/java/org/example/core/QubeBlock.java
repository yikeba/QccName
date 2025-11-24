package org.example.core;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class QubeBlock {

    private final int blockNumber;          // 区块编号
    private final String previousHash;       // 上一个区块哈希
    private final int maxTxCount;            // 最大交易条数
    private final long maxSizeBytes;         // 最大区块大小
    private final long maxDurationMillis;    // 最大区块生命周期
    private long creationTime;               // 区块实例创建时间
    private long timestamp;                  // 区块头记录时间

    private final List<byte[]> transactions; // 交易数据列表
    private String hash;                     // 区块哈希

    // ====================== 构造函数 ======================

    public QubeBlock(int blockNumber, String previousHash) {
        this(blockNumber, previousHash, 10000, 2 * 1024 * 1024, 3000);
    }

    public QubeBlock(int blockNumber, String previousHash, int maxTxCount,
                     long maxSizeBytes, long maxDurationMillis) {
        this.blockNumber = blockNumber;
        this.previousHash = previousHash;
        this.maxTxCount = maxTxCount;
        this.maxSizeBytes = maxSizeBytes;
        this.maxDurationMillis = maxDurationMillis;
        this.creationTime = System.currentTimeMillis();
        this.timestamp = creationTime;
        this.transactions = new ArrayList<>();
    }

    // ====================== 核心方法 ======================

    public boolean addTransaction(byte[] tx) {
        if (transactions.size() >= maxTxCount) return false;
        if (currentSize() + tx.length > maxSizeBytes) return false;
        transactions.add(tx);
        return true;
    }

    public long currentSize() {
        long size = 0;
        for (byte[] tx : transactions) {
            size += tx.length;
        }
        return size;
    }

    public boolean isFull() {
        long now = System.currentTimeMillis();
        return transactions.size() >= maxTxCount
                || currentSize() >= maxSizeBytes
                || (now - creationTime) >= maxDurationMillis;
    }

    /** 完成区块哈希计算 */
    public void finalizeBlock(String blockHash) {
        this.hash = blockHash;
    }

    // ====================== JSON 可视化 ======================

    public String toJSON() {
        StringBuilder txsJson = new StringBuilder("[");
        for (int i = 0; i < transactions.size(); i++) {
            if (i > 0) txsJson.append(",");
            txsJson.append("\"").append(transactions.get(i).length).append(" bytes").append("\"");
        }
        txsJson.append("]");

        return String.format(
                """
                {
                  "blockNumber": %d,
                  "previousHash": "%s",
                  "creationTime": "%s",
                  "timestamp": "%s",
                  "transactions": %s,
                  "hash": "%s"
                }
                """,
                blockNumber,
                previousHash,
                TimestampUtil.encode(creationTime),
                TimestampUtil.encode(timestamp),
                txsJson,
                hash
        );
    }

    public byte[] toBytes() {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(baos)) {

            // 基本信息
            dos.writeLong(blockNumber);
            writeString(dos, previousHash);
            dos.writeLong(creationTime);
            dos.writeLong(timestamp);

            // 交易列表
            dos.writeInt(transactions.size());
            for (byte[] tx : transactions) {
                dos.writeInt(tx.length);
                dos.write(tx);
            }

            // 区块哈希
            writeString(dos, hash != null ? hash : "");

            dos.flush();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("QubeBlock序列化失败", e);
        }
    }

    /** 返回区块哈希字节数组，用于索引存储 */
    public byte[] getHashBytes() {
        if(hash == null) return new byte[32]; // 占位
        byte[] h = hash.getBytes(StandardCharsets.UTF_8);
        byte[] bytes32 = new byte[32];
        System.arraycopy(h, 0, bytes32, 0, Math.min(h.length, 32));
        return bytes32;
    }

    /** 工具方法：写字符串 */
    private void writeString(DataOutputStream dos, String s) throws IOException {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        dos.writeInt(bytes.length);
        dos.write(bytes);
    }



    // ====================== Getter / Setter ======================

    public int getBlockNumber() { return blockNumber; }
    public String getPreviousHash() { return previousHash; }
    public int getMaxTxCount() { return maxTxCount; }
    public long getMaxSizeBytes() { return maxSizeBytes; }
    public long getMaxDurationMillis() { return maxDurationMillis; }
    public long getCreationTime() { return creationTime; }
    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
    public List<byte[]> getTransactions() { return transactions; }
    public String getHash() { return hash; }
}
