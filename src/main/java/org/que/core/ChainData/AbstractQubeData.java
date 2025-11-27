// AbstractQubeData.java —— 三类数据唯一父类（永不翻车）
package org.que.core.ChainData;

import org.que.crypto.CryptoUtil;
import java.io.*;
import java.nio.charset.StandardCharsets;

public abstract class AbstractQubeData {

    // ==================== 所有数据都有的基础字段 ====================
    protected final ChainDataType type;           // 数据类型：TRADE / RULE / ENTITY
    protected long timestamp;                     // 创建时间（支持反序列化修改）
    protected final long feeAmount;               // 手续费
    protected final byte[] senderPubKey;          // 发送者公钥
    protected final byte[] signature;             // 完整签名
    protected final byte[] contractAddress;

    private transient byte[] payloadHash;          // payload 的 SHA3-256
    byte[] originalPayloadHash;  // 原始哈希，来自链上
    protected AbstractQubeData(ChainDataType type, long feeAmount, byte[] senderPubKey, byte[] signature, byte[] contractAddress) {
        this.type = type;
        this.contractAddress = contractAddress;
        this.timestamp = System.currentTimeMillis();
        this.feeAmount = feeAmount;
        this.senderPubKey = senderPubKey != null ? senderPubKey.clone() : new byte[0];
        this.signature = signature != null ? signature.clone() : new byte[0];
    }



    // 子类实现：业务字段 → byte[]
    protected abstract byte[] serializePayload() throws IOException;
    protected abstract void deserializePayload(DataInputStream dis) throws IOException;

    // 强制要求实现：人类可读日志 + 前端JSON
    public abstract String toAuditString();   // 必须！给人看！审计必备！
    public abstract String toJSON();          // 必须！给前端看！



    public byte[] getContractAddress() { return contractAddress; }

    // ==================== 全局统一序列化 ====================
    public final byte[] toByteArray() throws IOException {
        byte[] payload = serializePayload();
        payloadHash = CryptoUtil.sha3256(payload);

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(baos)) {
            dos.writeByte(type.typeId);
            dos.writeLong(timestamp);
            dos.writeLong(feeAmount);
            writeVarBytes(dos, senderPubKey);
            writeVarBytes(dos, signature);
            dos.write(payloadHash);
            // ⭐⭐ 新增：合约地址序列化
            writeVarBytes(dos, contractAddress);
            dos.writeInt(payload.length);
            dos.write(payload);
            return baos.toByteArray();
        }
    }


    // 公开 getter，供子类在 verifyIntegrity() 时使用
    protected final byte[] getOriginalPayloadHash() {
        return this.originalPayloadHash != null ? this.originalPayloadHash.clone() : null;
    }

   /* // ==================== 全局统一反序列化入口（最硬！） ====================
    public static AbstractQubeData parseFrom(byte[] data) throws IOException {
        if (data == null || data.length < 60) throw new IOException("数据太短");
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
        byte typeId = dis.readByte();
        ChainDataType type = ChainDataType.fromId(typeId);

        long timestamp = dis.readLong();
        long feeAmount = dis.readLong();
        byte[] pubKey = readVarBytes(dis);
        byte[] sig = readVarBytes(dis);
        byte[] hash = new byte[32];
        dis.readFully(hash);

        // ⭐⭐⭐ 新增：读取 contractAddress
        byte[] contractAddress = readVarBytes(dis);
        if (contractAddress.length == 0) {
            throw new IOException("反序列化时 contractAddress 为空！");
        }

        int len = dis.readInt();
        byte[] payload = new byte[len];
        dis.readFully(payload);

        if (!Arrays.equals(hash, CryptoUtil.sha3256(payload))) {
            throw new IOException("数据被篡改！Payload哈希不匹配");
        }

        // 路由到具体类解析
        AbstractQubeData record = switch (type) {
            case TRADE  -> TradeRecord.parseFrom(data);
            case RULE   -> RuleRecord.parseFrom(data);
            case ENTITY -> EntityRecord.parseFrom(data);
        };
        record.setTimestamp(timestamp);
        return record;
    }*/

    /** 带记录长度的序列化（用于写入 BlockData） */
    public final byte[] toRecordBytes() throws IOException {
        byte[] core = toByteArray(); // 原本的记录内容（带 typeId, timestamp, sig, payload 等）
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(core.length);   // ⭐ 关键：写入记录长度
        dos.write(core);             // ⭐ 写入记录内容
        return baos.toByteArray();
    }


    // 工具方法
    protected static void writeVarBytes(DataOutputStream dos, byte[] b) throws IOException {
        dos.writeInt(b == null ? 0 : b.length);
        if (b != null && b.length > 0) dos.write(b);
    }
    protected static byte[] readVarBytes(DataInputStream dis) throws IOException {
        int len = dis.readInt();
        if (len == 0) return new byte[0];
        byte[] b = new byte[len];
        dis.readFully(b);
        return b;
    }
    protected static String readString(DataInputStream dis) throws IOException {
        byte[] b = readVarBytes(dis);
        return b.length == 0 ? "" : new String(b, StandardCharsets.UTF_8);
    }
    protected static void writeString(DataOutputStream dos, String s) throws IOException {
        writeVarBytes(dos, s == null ? null : s.getBytes(StandardCharsets.UTF_8));
    }

    protected void setTimestamp(long ts) { this.timestamp = ts; }
    public ChainDataType getType() { return type; }

    // 抽象方法：子类必须自己实现完整性校验！
    public abstract boolean verifyIntegrity();


    // 加到 AbstractQubeData.java 中（所有子类都能用）
    public byte[] getSenderPubKey() {
        return senderPubKey != null ? senderPubKey.clone() : new byte[0];
    }
}