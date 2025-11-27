package org.que.core.block;

import com.alibaba.fastjson2.JSONWriter;
import com.alibaba.fastjson2.JSONObject;

import java.io.IOException;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.HexFormat;

/**
 * BlockHead v11 - 生产级区块头部（固定 96 字节）
 * 职责：元信息 + 哈希链连接 + 快速定位
 * 特性：完全不可变、零拷贝序列化、严格校验、可视化友好
 */
public final class BlockHead implements Serializable {

    @java.io.Serial
    private static final long serialVersionUID = 20251125L;

    // ====================== 固定结构（96 字节）======================
    private static final int MAGIC      = 0x51554245; // "QUBE"
    private static final byte VERSION   = 11;
    private static final byte[] RESERVED = new byte[31]; // 全0预留

    // ====================== 不可变字段 ======================
    private final int    blockNumber;     // 容器内相对编号
    private final String previousHash;    // 64字符小写hex，上一个区块的 currentHash
    private final long   creationTime;    // 区块开始生成时间（ms）
    private final long   sealTime;        // 封块时间（ms）
    private final int    recordCount;     // DataArea 中记录条数
    private final int    dataAreaSize;    // DataArea 实际字节数

    // ====================== 私有构造器 ======================
    private BlockHead(int blockNumber,
                      String previousHash,
                      long creationTime,
                      long sealTime,
                      int recordCount,
                      int dataAreaSize) {
        this.blockNumber    = blockNumber;
        this.previousHash   = previousHash;
        this.creationTime   = creationTime;
        this.sealTime       = sealTime;
        this.recordCount    = recordCount;
        this.dataAreaSize   = dataAreaSize;
    }

    // ====================== 1. 静态创建（推荐）======================
    public static BlockHead create(int blockNumber,
                                   String previousHash,
                                   int recordCount,
                                   int dataAreaSize) {
        return new BlockHead(
                blockNumber,
                validateAndNormalizeHash(previousHash),
                System.currentTimeMillis(),
                System.currentTimeMillis(),
                recordCount,
                dataAreaSize
        );
    }

    // ====================== 2. 静态解析（唯一反序列化入口）======================
    public static BlockHead fromBytes(byte[] bytes) throws IOException {
        if (bytes == null || bytes.length < 96) {
            throw new IOException("BlockHead 数据不足 96 字节");
        }

        ByteBuffer buf = ByteBuffer.wrap(bytes, 0, 96);

        if (buf.getInt() != MAGIC) {
            throw new IOException("无效的 QUBE 区块魔数: 0x" + Integer.toHexString(buf.getInt(0)));
        }
        if (buf.get() != VERSION) {
            throw new IOException("不支持的 BlockHead 版本: " + buf.get(4));
        }

        int blockNumber = buf.getInt();
        byte[] hashRaw = new byte[32];
        buf.get(hashRaw);
        String previousHash = HexFormat.of().formatHex(hashRaw); // 自动转小写

        long creationTime = buf.getLong();
        long sealTime     = buf.getLong();
        int recordCount   = buf.getInt();
        int dataAreaSize  = buf.getInt();

        // 跳过 reserved 区（不再读取，已知全0）

        BlockHead head = new BlockHead(blockNumber, previousHash, creationTime, sealTime, recordCount, dataAreaSize);
        if (!head.validate()) {
            throw new IOException("BlockHead 内容校验失败");
        }
        return head;
    }

    // ====================== 3. 序列化（零拷贝）======================
    public byte[] toBytes() {
        ByteBuffer buf = ByteBuffer.allocate(96);
        buf.putInt(MAGIC);
        buf.put(VERSION);
        buf.putInt(blockNumber);
        buf.put(HexFormat.of().parseHex(previousHash)); // 64 hex → 32 bytes
        buf.putLong(creationTime);
        buf.putLong(sealTime);
        buf.putInt(recordCount);
        buf.putInt(dataAreaSize);
        buf.put(RESERVED);
        return buf.array();
    }

    // ====================== 4. 内容校验 ======================
    public boolean validate() {
        return blockNumber >= 0
                && previousHash.length() == 64
                && previousHash.matches("[0-9a-f]{64}")
                && recordCount >= 0
                && dataAreaSize >= 0
                && creationTime > 0
                && sealTime >= creationTime;
    }

    // ====================== 5. 可视化 ======================
    public String toJson() {
        JSONObject json = new JSONObject();
        json.put("blockNumber", blockNumber);
        json.put("previousHash", previousHash);
        json.put("creationTime", creationTime);
        json.put("sealTime", sealTime);
        json.put("recordCount", recordCount);
        json.put("dataAreaSize", dataAreaSize);
        return json.toJSONString(JSONWriter.Feature.PrettyFormat);
    }

    public String toAuditString() {
        return String.format("Head{#%d ← %s... | %,d 条记录 | %,d bytes | %tc}",
                blockNumber,
                previousHash.substring(0, 12),
                recordCount,
                dataAreaSize,
                sealTime);
    }

    // ====================== Getter（只读）======================
    public int    getBlockNumber()    { return blockNumber; }
    public String getPreviousHash()   { return previousHash; }
    public long   getCreationTime()   { return creationTime; }
    public long   getSealTime()       { return sealTime; }
    public int    getRecordCount()    { return recordCount; }
    public int    getDataAreaSize()   { return dataAreaSize; }

    // ====================== 工具方法 ======================
    private static String validateAndNormalizeHash(String hash) {
        if (hash == null || hash.isEmpty() || "0".repeat(64).equals(hash)) {
            return "0".repeat(64);
        }
        if (hash.length() != 64) {
            throw new IllegalArgumentException("previousHash 必须为 64 字符 hex 字符串");
        }
        if (!hash.matches("[0-9a-fA-F]{64}")) {
            throw new IllegalArgumentException("previousHash 包含非法字符");
        }
        return hash.toLowerCase();
    }

    @Override
    public String toString() {
        return toAuditString();
    }
}
