package org.que.core.container;

import java.io.*;

public final class ContainerIndexEntry {

    // =================== 固定长度 ===================
    public static final int FIXED_SIZE = 4 + 8 + 4 + 32;
    // height:int + offset:long + length:int + hash:32

    // =================== 字段 ===================
    private final int height;
    private final long offset;
    private final int length;
    private final byte[] blockHash; // always 32 bytes

    // =================== 1. 创建构建 ===================
    public ContainerIndexEntry(int height, long offset, int length, byte[] blockHash) {
        if (blockHash == null || blockHash.length != 32) {
            throw new IllegalArgumentException("blockHash 必须为 32 字节");
        }
        this.height = height;
        this.offset = offset;
        this.length = length;
        this.blockHash = blockHash.clone();
    }

    // =================== 2. 解析构建 ===================
    public static ContainerIndexEntry parse(DataInput in) throws IOException {
        int height = in.readInt();
        long offset = in.readLong();
        int length = in.readInt();
        byte[] hash = new byte[32];
        in.readFully(hash);
        return new ContainerIndexEntry(height, offset, length, hash);
    }

    // =================== 3. 序列化 ===================
    public byte[] toBytes() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(FIXED_SIZE);
        DataOutputStream dos = new DataOutputStream(baos);

        dos.writeInt(height);
        dos.writeLong(offset);
        dos.writeInt(length);
        dos.write(blockHash);

        return baos.toByteArray();
    }

    // =================== 4. JSON 输出 ===================
    public String toJSON() {
        return String.format(
                "{ \"height\": %d, \"offset\": %d, \"length\": %d, \"hash\": \"%s\" }",
                height, offset, length, hex(blockHash)
        );
    }

    // =================== 5. 审计模式 ===================
    public String toAuditString() {
        return String.format(
                "IndexEntry[h=%d, off=%d, len=%d, hash=%s]",
                height, offset, length, shortHash()
        );
    }

    // =================== 6. 工具 ===================
    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private String shortHash() {
        String h = hex(blockHash);
        return h.substring(0,8) + "..." + h.substring(h.length()-8);
    }

    // =================== 7. Getter ===================
    public int getHeight() { return height; }
    public long getOffset() { return offset; }
    public int getLength() { return length; }
    public byte[] getBlockHash() { return blockHash.clone(); }

    // =================== 8. 验证 ===================
    public void validate() throws IOException {
        if (offset < 256) throw new IOException("IndexEntry offset 不可能小于 head 大小");
        if (length <= 0) throw new IOException("IndexEntry length 非法");
        if (blockHash.length != 32) throw new IOException("hash 长度错误");
    }
}

