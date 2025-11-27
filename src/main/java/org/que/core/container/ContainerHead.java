package org.que.core.container;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * ContainerHead
 *
 * 容器头信息：
 * - 描述容器文件的基本结构和元信息
 * - 当前版本依然与现有 Container.java 的读写格式兼容：
 *   magic(4) + version(2) + containerHash(32) + baseTime(8)
 *   + blockCount(4) + indexOffset(8) + indexLength(8) + reserved(...)
 *
 * 同时预留更高级字段（containerId / contractAddress / flags ...），
 * 方便后续升级为“进程级容器模型”。
 */
public class ContainerHead implements Cloneable {

    // ===================== 常量区 =====================

    /** 固定头大小（字节）—— 与旧实现保持 256 字节不变 */
    public static final int FIXED_SIZE = 256;

    /** 文件头标识 */
    public static final String MAGIC = "QUBE";

    /** 协议版本 */
    public static final short CURRENT_VERSION = 1;

    // ===================== 旧版本字段（保持兼容） =====================

    /** 魔数，用于快速识别容器文件 */
    public String magic = MAGIC;          // 4 bytes

    /** 容器头版本号 */
    public short version = CURRENT_VERSION;   // 2 bytes

    /** 容器整体哈希（由 ContainerFooter 计算后回写） */
    public byte[] containerHash = new byte[32];   // 32 bytes

    /** 基础时间戳（旧设计，用于区块时间压缩等） */
    public long baseTime;                  // 8 bytes

    /** 区块数量（用于快速遍历） */
    public int blockCount;                 // 4 bytes

    /** 索引区起始偏移 */
    public long indexOffset;               // 8 bytes

    /** 索引区长度 */
    public long indexLength;               // 8 bytes

    /** 创建时间（短字符串编码），人类辅助阅读 */
    public String createTime;

    /**
     * 填充到 FIXED_SIZE 的保留字段
     * 当前实现：FIXED_SIZE - (4 + 2 + 32 + 8 + 4 + 8 + 8)
     */
    public byte[] reserved = new byte[FIXED_SIZE - 4 - 2 - 32 - 8 - 4 - 8 - 8];

    // ===================== 新模型预留字段（暂不写入磁盘） =====================

    /** 容器唯一 ID（推荐为 head 关键字段的 SHA3-256） */
    private byte[] containerId;           // 32 bytes 建议值

    /** 容器归属的合约地址 / 企业地址 */
    private byte[] contractAddress;       // 建议 20~32 bytes

    /** 容器 flags：public/private/encrypted 等位标志 */
    private int flags;

    /** 创建时间（毫秒级）—— 比 createTime 更精确 */
    private long createdAt;

    /** 封存时间（毫秒，0 表示未封存） */
    private long sealedAt;

    /** 数据区起始偏移（将来可用） */
    private long dataAreaOffset;

    /** 数据区长度（将来可用） */
    private long dataAreaSize;

    /** 索引区起始偏移（新模型中与 indexOffset 一致，可逐步替代） */
    private long indexAreaOffset;

    /** 索引区长度（新模型中与 indexLength 一致，可逐步替代） */
    private long indexAreaSize;

    /** 容器属性对象 —— 权限、加密、ACL 等 */
    private ContainerAttributes attributes;

    // ===================== 1. 创建构建 =====================

    /**
     * 创建一个新的 ContainerHead（新建容器时用）
     *
     * @param contractAddress 合约/企业地址
     * @param baseTimeMillis  基础时间戳（通常 System.currentTimeMillis()）
     * @param flags           标志位（public/private/encrypted 等）
     */
    public static ContainerHead createNew(byte[] contractAddress, long baseTimeMillis, int flags) {
        ContainerHead head = new ContainerHead();
        head.magic = MAGIC;
        head.version = CURRENT_VERSION;
        head.baseTime = baseTimeMillis;
        head.blockCount = 0;
        head.indexOffset = 0;
        head.indexLength = 0;
        head.contractAddress = contractAddress != null ? contractAddress.clone() : null;
        head.flags = flags;
        head.createdAt = System.currentTimeMillis();
        head.sealedAt = 0L;
        // createTime 可以由外部调用 TimestampUtil.encode 来填
        return head;
    }

    /** 无参构造，反序列化用 */
    public ContainerHead() {
    }

    // ===================== 2. 解析构建 =====================

    /**
     * 从 DataInput（如 RandomAccessFile）中解析容器头。
     * 当前只解析旧格式字段，保持与现有 Container.readHead 兼容。
     */
    public static ContainerHead parseFrom(DataInput in) throws IOException {
        ContainerHead h = new ContainerHead();

        byte[] magicBytes = new byte[4];
        in.readFully(magicBytes);
        h.magic = new String(magicBytes, StandardCharsets.UTF_8);

        h.version = in.readShort();

        byte[] hash = new byte[32];
        in.readFully(hash);
        h.containerHash = hash;

        h.baseTime = in.readLong();
        h.blockCount = in.readInt();
        h.indexOffset = in.readLong();
        h.indexLength = in.readLong();

        byte[] reserved = new byte[FIXED_SIZE - 4 - 2 - 32 - 8 - 4 - 8 - 8];
        in.readFully(reserved);
        h.reserved = reserved;

        // 校验基础合法性
        h.validate();
        return h;
    }

    // ===================== 3. 二进制序列化 =====================

    /**
     * 序列化为字节数组，布局必须与 parseFrom 对称，保持 FIXED_SIZE 固定长度。
     */
    public byte[] toBytes() throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(FIXED_SIZE);
             DataOutputStream dos = new DataOutputStream(baos)) {

            // magic
            byte[] magicBytes = magic != null ? magic.getBytes(StandardCharsets.UTF_8)
                    : MAGIC.getBytes(StandardCharsets.UTF_8);
            if (magicBytes.length != 4) {
                throw new IOException("magic 必须是4字节，当前长度=" + magicBytes.length);
            }
            dos.write(magicBytes);

            // version
            dos.writeShort(version);

            // containerHash
            if (containerHash == null || containerHash.length != 32) {
                throw new IOException("containerHash 必须是32字节");
            }
            dos.write(containerHash);

            // baseTime / blockCount / indexOffset / indexLength
            dos.writeLong(baseTime);
            dos.writeInt(blockCount);
            dos.writeLong(indexOffset);
            dos.writeLong(indexLength);

            // reserved
            if (reserved == null) {
                reserved = new byte[FIXED_SIZE - 4 - 2 - 32 - 8 - 4 - 8 - 8];
            }
            if (reserved.length != FIXED_SIZE - 4 - 2 - 32 - 8 - 4 - 8 - 8) {
                throw new IOException("reserved 长度不正确，应为 "
                        + (FIXED_SIZE - 4 - 2 - 32 - 8 - 4 - 8 - 8) + " 字节");
            }
            dos.write(reserved);

            byte[] result = baos.toByteArray();
            if (result.length != FIXED_SIZE) {
                throw new IOException("ContainerHead 序列化长度错误，应为 "
                        + FIXED_SIZE + "，实际为 " + result.length);
            }
            return result;
        }
    }

    // ===================== 4. 校验方法 =====================

    /**
     * 校验头部字段的基本合法性。
     */
    public void validate() throws IOException {
        if (magic == null || magic.length() != 4) {
            throw new IOException("非法 magic: " + magic);
        }
        if (containerHash == null || containerHash.length != 32) {
            throw new IOException("containerHash 长度必须为32字节");
        }
        if (reserved == null ||
                reserved.length != FIXED_SIZE - 4 - 2 - 32 - 8 - 4 - 8 - 8) {
            throw new IOException("reserved 长度不匹配");
        }
    }

    // ===================== 5. 估算大小 =====================

    /**
     * 预估序列化之后的大小，当前为固定 256 字节。
     */
    public int estimateSize() {
        return FIXED_SIZE;
    }

    // ===================== 6. 人类可读输出 =====================

    /**
     * JSON 风格字符串，方便在日志 / API 中查看。
     */
    public String toJSON() {
        return String.format(
                "{ \"magic\": \"%s\", \"version\": %d, \"baseTime\": %d, " +
                        "\"blockCount\": %d, \"indexOffset\": %d, \"indexLength\": %d, " +
                        "\"containerHash\": \"%s\" }",
                magic,
                (int) version,
                baseTime,
                blockCount,
                indexOffset,
                indexLength,
                bytesToHex(containerHash)
        );
    }

    /**
     * 审计友好（单行可读），便于在没有任何 UI 的环境输出。
     */
    public String toAuditString() {
        return String.format(
                "ContainerHead[magic=%s, ver=%d, blocks=%d, index@%d+%d, hash=%s]",
                magic,
                (int) version,
                blockCount,
                indexOffset,
                indexLength,
                shortHash(containerHash)
        );
    }

    private static String shortHash(byte[] hash) {
        if (hash == null || hash.length == 0) return "-";
        String hex = bytesToHex(hash);
        if (hex.length() <= 16) return hex;
        return hex.substring(0, 8) + "..." + hex.substring(hex.length() - 8);
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // ===================== 7. 克隆 / 深拷贝 =====================

    @Override
    public ContainerHead clone() {
        try {
            ContainerHead copy = (ContainerHead) super.clone();
            copy.containerHash = containerHash != null ? containerHash.clone() : null;
            copy.reserved = reserved != null ? reserved.clone() : null;
            copy.contractAddress = contractAddress != null ? contractAddress.clone() : null;
            copy.containerId = containerId != null ? containerId.clone() : null;
            if (attributes != null) {
                copy.attributes = attributes.clone();
            }
            return copy;
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    // ===================== 8. Getter / Setter（关键字段） =====================

    public byte[] getContainerId() {
        return containerId;
    }

    public void setContainerId(byte[] containerId) {
        this.containerId = containerId;
    }

    public byte[] getContractAddress() {
        return contractAddress;
    }

    public void setContractAddress(byte[] contractAddress) {
        this.contractAddress = contractAddress;
    }

    public int getFlags() {
        return flags;
    }

    public void setFlags(int flags) {
        this.flags = flags;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    public long getSealedAt() {
        return sealedAt;
    }

    public void setSealedAt(long sealedAt) {
        this.sealedAt = sealedAt;
    }

    public long getDataAreaOffset() {
        return dataAreaOffset;
    }

    public void setDataAreaOffset(long dataAreaOffset) {
        this.dataAreaOffset = dataAreaOffset;
    }

    public long getDataAreaSize() {
        return dataAreaSize;
    }

    public void setDataAreaSize(long dataAreaSize) {
        this.dataAreaSize = dataAreaSize;
    }

    public long getIndexAreaOffset() {
        return indexAreaOffset;
    }

    public void setIndexAreaOffset(long indexAreaOffset) {
        this.indexAreaOffset = indexAreaOffset;
    }

    public long getIndexAreaSize() {
        return indexAreaSize;
    }

    public void setIndexAreaSize(long indexAreaSize) {
        this.indexAreaSize = indexAreaSize;
    }

    public ContainerAttributes getAttributes() {
        return attributes;
    }

    public void setAttributes(ContainerAttributes attributes) {
        this.attributes = attributes;
    }
}
