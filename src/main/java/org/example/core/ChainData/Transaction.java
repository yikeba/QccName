package org.example.core.ChainData;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.util.encoders.Hex;

/**
 * Transaction: 0x01 类型，用于价值转移和资产状态变更。
 */
public class Transaction extends AbstractQubeData {

    private final byte[] toPubkey;
    private final long amount;
    private final int assetId;
    private final String memo;

    // ====================== 构造函数 ======================
    public Transaction(
            byte[] toPubkey,
            long amount,
            int assetId,
            String memo,
            long feeAmount,
            byte[] senderPubKey,
            byte[] signature) {

        // 调用父类构造函数，设置 TypeID = 0x01
        super(ChainData.TYPE_ID_TRANSACTION, feeAmount, senderPubKey, signature);

        // 验证关键字段
        if (toPubkey == null || toPubkey.length == 0 || amount <= 0) {
            throw new IllegalArgumentException("Transaction requires valid ToPubKey and positive Amount.");
        }

        this.toPubkey = toPubkey;
        this.amount = amount;
        this.assetId = assetId;
        this.memo = (memo != null) ? memo : "";
    }

    // ====================== 核心序列化与解析 ======================

    /**
     * 【核心实现】定义 Payload Body 的写入顺序和结构。
     */
    @Override
    protected byte[] getPayloadBody() throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(baos)) {
            // 1. 写入 ToPubkey (注意：Dilithium 公钥长度通常是固定的，此处我们直接写入 byte[])
            dos.write(toPubkey);
            // 2. 写入 Amount 和 AssetID
            dos.writeLong(amount);
            dos.writeInt(assetId);
            // 3. 写入 Memo (写入长度 + 写入内容)
            byte[] memoBytes = memo.getBytes(StandardCharsets.UTF_8);
            dos.writeInt(memoBytes.length);
            dos.write(memoBytes);
            dos.flush();
            return baos.toByteArray();
        }
    }

    /**
     * 【标准 1：快速构造/验证】静态工厂方法，用于从 byte[] 反序列化。
     */
    public static Transaction parseFrom(byte[] fullDataBytes) throws IOException {
        // [TODO: 实现细节] 需要实现完整的 Header 和 Payload Body 的反序列化逻辑
        // 重点是：确保 toPubkey, amount, assetId, memo 的读取顺序和长度与 getPayloadBody() 严格一致。
        throw new UnsupportedOperationException("Transaction Deserialization TBD.");
    }

    // ====================== 可视化方法 (标准 3) ======================

    @Override
    public String toAuditString() {
        return String.format("Transaction [AssetID=%d, Amount=%d, To=%s, Fee=%d]",
                this.assetId,
                this.amount,
                Hex.toHexString(this.toPubkey).substring(0, 10) + "...",
                this.feeAmount);
    }

    @Override
    public String toJSON() {
        return String.format(
                """
                {
                  "typeId": "%s",
                  "timestamp": %d,
                  "senderPubKey": "%s",
                  "toPubkey": "%s",
                  "amount": %d,
                  "assetId": %d,
                  "feeAmount": %d
                }
                """,
                Hex.toHexString(new byte[]{this.typeId}),
                this.timestamp,
                Hex.toHexString(this.senderPubKey),
                Hex.toHexString(this.toPubkey),
                this.amount,
                this.assetId,
                this.feeAmount
        );
    }
}