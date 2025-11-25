package org.example.core.block;

import com.alibaba.fastjson2.JSONObject;
import org.example.crypto.CryptoUtil;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * BlockFoot v1 - 区块尾部（固定 72 字节）
 * 职责：
 *   1. 存储当前区块完整哈希（64字符 hex）
 *   2. 存储结束魔数 "ENDQ"（4字节）
 *   3. 提供校验：传入 (Head + Data) 的哈希，验证是否匹配
 */
public final class BlockFoot implements Serializable {

    @java.io.Serial
    private static final long serialVersionUID = 20251125L;

    private static final byte[] END_MAGIC = "ENDQ".getBytes(StandardCharsets.UTF_8); // 4字节

    // 当前区块完整哈希：SHA256d(Head + Data) 的 hex 字符串（64字符）
    private final String currentHash;


    public BlockFoot(String currentHash) {
        this.currentHash = validateHash(currentHash);
    }

    // ====================== 1. 静态创建（由 QubeBlock 调用）======================
    public static BlockFoot create(byte[] headBytes, byte[] dataBytes) {
        byte[] combined = new byte[headBytes.length + dataBytes.length];
        System.arraycopy(headBytes, 0, combined, 0, headBytes.length);
        System.arraycopy(dataBytes, 0, combined, headBytes.length, dataBytes.length);

        byte[] hash = CryptoUtil.sha256(combined);  // 双SHA256
        String hexHash = bytesToHex(hash);
        return new BlockFoot(hexHash);
    }

    // ====================== 2. 静态解析（从 byte[] 还原）======================
    public static BlockFoot fromBytes(byte[] bytes) throws IOException {
        if (bytes == null || bytes.length < 72) {
            throw new IOException("BlockFoot 数据不足 72 字节");
        }

        ByteBuffer buf = ByteBuffer.wrap(bytes);
        byte[] hashBytes = new byte[64];
        buf.get(hashBytes);
        String hash = new String(hashBytes, StandardCharsets.UTF_8);

        byte[] magic = new byte[4];
        buf.get(magic);
        if (!Arrays.equals(magic, END_MAGIC)) {
            throw new IOException("BlockFoot 结束魔数错误");
        }

        BlockFoot foot = new BlockFoot(hash);
        if (!foot.validate()) throw new IOException("BlockFoot 校验失败");
        return foot;
    }

    // ====================== 3. 序列化（固定 72 字节）======================
    public byte[] toBytes() {
        ByteBuffer buf = ByteBuffer.allocate(72);
        buf.put(currentHash.getBytes(StandardCharsets.UTF_8));
        buf.put(END_MAGIC);
        buf.put(new byte[4]); // 预留4字节未来扩展
        return buf.array();
    }

    // ====================== 4. 校验：当前哈希是否正确 ======================
    public boolean verify(byte[] headBytes, byte[] dataBytes) {
        byte[] combined = new byte[headBytes.length + dataBytes.length];
        System.arraycopy(headBytes, 0, combined, 0, headBytes.length);
        System.arraycopy(dataBytes, 0, combined, headBytes.length, dataBytes.length);

        byte[] expected = CryptoUtil.sha256(combined);
        return currentHash.equals(bytesToHex(expected));
    }

    // ====================== 5. 可视化 ======================
    public String toJson() {
        JSONObject json = new JSONObject();
        json.put("currentHash", currentHash);
        json.put("magic", "ENDQ");
        return json.toString();
    }

    public String toAuditString() {
        return String.format("Foot[hash=%s... %s]", currentHash.substring(0, 16), "ENDQ");
    }

    // ====================== Getter ======================
    public String getCurrentHash() { return currentHash; }

    // ====================== 工具方法 ======================
    private boolean validate() {
        return currentHash.length() == 64 && currentHash.matches("[0-9a-f]{64}");
    }

    private static String validateHash(String h) {
        if (h == null || h.length() != 64 || !h.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("BlockFoot hash 必须是 64 字符小写 hex");
        }
        return h;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Override
    public String toString() { return toAuditString(); }
}