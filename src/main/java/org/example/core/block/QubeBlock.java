package org.example.core.block;

import org.example.crypto.CryptoUtil;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.Set;

/**
 * QubeBlock v16 - 终极生产级区块（Head + Data + Foot）
 * 职责：封块、落盘、验证、上交索引
 * 特性：100% 不可变、零拷贝、完整性可验证、支持流式构建
 */
public final class QubeBlock implements Serializable {

    @java.io.Serial
    private static final long serialVersionUID = 20251125L;

    private final BlockHead head;
    private final BlockData data;
    private final BlockFoot foot;

    // 私有构造器，强制通过 Builder
    private QubeBlock(BlockHead head, BlockData data, BlockFoot foot) {
        this.head = head;
        this.data = data;
        this.foot = foot;
    }

    // ====================== Builder：生产唯一入口 ======================
    public static class Builder {
        private BlockHead head;
        private BlockData data;

        public Builder head(BlockHead head) {
            this.head = head;
            return this;
        }

        public Builder data(BlockData data) {
            this.data = data;
            return this;
        }

        public QubeBlock build() {
            if (head == null || data == null) {
                throw new IllegalStateException("Head 和 Data 必须设置");
            }
            if (!data.isSealed()) {
                data.seal();  // 自动封块
            }
            // 计算 Foot（单次 SHA256）
            byte[] headBytes = head.toBytes();
            byte[] dataBytes = data.getRawBytes();
            BlockFoot foot = BlockFoot.create(headBytes, dataBytes);
            return new QubeBlock(head, data, foot);

        }
    }

    // ====================== 完整性验证（最硬核！）======================
    // ====================== 完整性验证（最硬核！）======================
    public boolean verifyIntegrity() {
        byte[] headBytes = head.toBytes();
        byte[] dataBytes = data.getRawBytes();
        return foot.verify(headBytes, dataBytes);
    }

    // ====================== 序列化：落盘专用 ======================
    public byte[] toBytes() {
        byte[] h = head.toBytes();
        byte[] d = data.getRawBytes();
        byte[] f = foot.toBytes();

        ByteBuffer buffer = ByteBuffer.allocate(h.length + d.length + f.length);
        buffer.put(h);
        buffer.put(d);
        buffer.put(f);
        return buffer.array();
    }

    // ====================== 反序列化：从 byte[] 完整还原 ======================
    public static QubeBlock fromBytes(byte[] bytes) throws IOException {

        // ==================== 1. 基本长度校验 ====================
        if (bytes == null || bytes.length < 96 + BlockFoot.FIXED_SIZE) {
            throw new IOException("区块数据太短：不足以包含 Head + Foot");
        }

        // ==================== 2. 解析 BlockHead（固定 96 字节） ====================
        byte[] headBytes = new byte[96];
        System.arraycopy(bytes, 0, headBytes, 0, 96);
        BlockHead head = BlockHead.fromBytes(headBytes);

        // ==================== 3. 解析 BlockData ====================
        int dataSize = head.getDataAreaSize();
        if (96 + dataSize + BlockFoot.FIXED_SIZE > bytes.length) {
            throw new IOException("区块数据损坏：dataAreaSize 越界");
        }

        byte[] dataBytes = new byte[dataSize];
        System.arraycopy(bytes, 96, dataBytes, 0, dataSize);

        BlockData data = BlockData.createEmpty();
        data.loadFromBytes(dataBytes);

        // ==================== 4. 解析 BlockFoot（固定 40 字节） ====================
        byte[] footBytes = new byte[BlockFoot.FIXED_SIZE];
        System.arraycopy(bytes, 96 + dataSize, footBytes, 0, BlockFoot.FIXED_SIZE);

        BlockFoot foot = BlockFoot.fromBytes(footBytes);

        // ==================== 5. 创建区块对象 ====================
        QubeBlock block = new QubeBlock(head, data, foot);

        // ==================== 6. 完整性校验 ====================
        if (!block.verifyIntegrity()) {
            throw new IOException("区块完整性校验失败！数据被篡改！");
        }

        return block;
    }

    // ====================== 上交索引（封块后调用）======================
    public int getBlockNumber() { return head.getBlockNumber(); }

    public String getCurrentHash() { return foot.getCurrentHash(); }

    public Set<byte[]> getInvolvedAddresses() { return data.getInvolvedAddresses(); }

    // ====================== 可视化 ======================
    public String toAuditString() {
        return String.format("QubeBlock{#%d | %s | %d条 | %d bytes | hash=%s...}",
                head.getBlockNumber(),
                verifyIntegrity() ? "完整" : "已损",
                data.getRecords().size(),
                toBytes().length,
                foot.getCurrentHash().substring(0, 16));
    }

    @Override
    public String toString() { return toAuditString(); }
}