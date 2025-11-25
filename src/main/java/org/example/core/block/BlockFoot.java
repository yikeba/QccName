package org.example.core.block;

import com.alibaba.fastjson2.JSONObject;
import org.example.crypto.CryptoUtil;

import java.io.IOException;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * BlockFoot v2 - 区块尾部（固定 40 字节）
 * 结构：
 *   [0  - 31]  currentHash   区块哈希原始 32 字节
 *   [32 - 35]  END_MAGIC     固定 "ENDQ"
 *   [36 - 39]  reserved      预留 4 字节（当前全 0）
 */
public final class BlockFoot implements Serializable {

    @java.io.Serial
    private static final long serialVersionUID = 20251125L;

    /** 固定魔数 "ENDQ" */
    private static final byte[] END_MAGIC = "ENDQ".getBytes(StandardCharsets.UTF_8);

    /** 尾部固定大小：32(hash) + 4(magic) + 4(reserved) */
    public static final int FIXED_SIZE = 40;

    /** 当前区块完整哈希：SHA256(Head + Data) 的原始 32 字节 */
    private final byte[] currentHash;

    public BlockFoot(byte[] currentHash) {
        this.currentHash = validateHash(currentHash);
    }

    // ====================== 1. 创建（由 QubeBlock 调用）======================
    public static BlockFoot create(byte[] headBytes, byte[] dataBytes) {
        byte[] combined = new byte[headBytes.length + dataBytes.length];
        System.arraycopy(headBytes, 0, combined, 0, headBytes.length);
        System.arraycopy(dataBytes, 0, combined, headBytes.length, dataBytes.length);

        byte[] hash = CryptoUtil.sha256(combined);  // 单次 SHA256
        return new BlockFoot(hash);
    }

    // ====================== 2. 反序列化 ======================
    public static BlockFoot fromBytes(byte[] bytes) throws IOException {
        if (bytes == null || bytes.length < FIXED_SIZE) {
            throw new IOException("BlockFoot 数据不足 " + FIXED_SIZE + " 字节");
        }

        ByteBuffer buf = ByteBuffer.wrap(bytes, 0, FIXED_SIZE);

        byte[] hashBytes = new byte[32];
        buf.get(hashBytes);

        byte[] magic = new byte[4];
        buf.get(magic);
        if (!Arrays.equals(magic, END_MAGIC)) {
            throw new IOException("BlockFoot 结束魔数错误");
        }

        // 预留 4 字节当前不使用，但要读过去保持位置一致
        byte[] reserved = new byte[4];
        buf.get(reserved);

        BlockFoot foot = new BlockFoot(hashBytes);
        if (!foot.validate()) {
            throw new IOException("BlockFoot 校验失败");
        }
        return foot;
    }

    // ====================== 3. 序列化（固定 40 字节） ======================
    public byte[] toBytes() {
        ByteBuffer buf = ByteBuffer.allocate(FIXED_SIZE);
        buf.put(currentHash);
        buf.put(END_MAGIC);
        buf.put(new byte[4]); // 预留 4 字节未来扩展
        return buf.array();
    }

    // ====================== 4. 校验 ======================
    public boolean verify(byte[] headBytes, byte[] dataBytes) {
        byte[] combined = new byte[headBytes.length + dataBytes.length];
        System.arraycopy(headBytes, 0, combined, 0, headBytes.length);
        System.arraycopy(dataBytes, 0, combined, headBytes.length, dataBytes.length);

        byte[] expected = CryptoUtil.sha256(combined);
        return Arrays.equals(currentHash, expected);
    }

    // ====================== 5. 可视化 ======================
    public String toJson() {
        JSONObject json = new JSONObject();
        json.put("currentHash", getCurrentHash()); // 仍然以 hex 展示
        json.put("magic", "ENDQ");
        return json.toString();
    }

    public String toAuditString() {
        String hex = getCurrentHash();
        return String.format("Foot[hash=%s... %s]", hex.substring(0, 16), "ENDQ");
    }

    // ====================== Getter ======================

    /** 对外还是给 64 位 hex，方便日志、索引使用 */
    public String getCurrentHash() {
        return bytesToHex(currentHash);
    }

    /** 原始 32 字节（防止被改，返回拷贝） */
    public byte[] getCurrentHashBytes() {
        return currentHash.clone();
    }

    // ====================== 工具方法 ======================
    private boolean validate() {
        return currentHash != null && currentHash.length == 32;
    }

    private static byte[] validateHash(byte[] h) {
        if (h == null || h.length != 32) {
            throw new IllegalArgumentException("BlockFoot hash 必须是 32 字节");
        }
        return h.clone();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return toAuditString();
    }
}
