package org.example.core.ChainData;


import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import org.bouncycastle.util.encoders.Hex;

/**
 * BalanceConfirmation: 0x02 类型, 0x01 子类型。
 * 由容器服务器生成和签名，用于证明 0x01 交易的余额计算结果。
 */
public class BalanceConfirmation extends AbstractQubeData {

    // 0x02 类型下的 0x01 子类型
    public static final byte SUB_TYPE_BALANCE_CONFIRMATION = 0x01;

    private final byte[] transactionHash;
    private final long senderFinalBalance;
    private final long receiverFinalBalance;
    private final byte[] containerServerID; // 签署确认记录的服务器 ID

    // ====================== 构造函数 ======================
    /**
     * @param transactionHash        被确认交易的哈希。
     * @param senderFinalBalance     交易后发送方的最终余额。
     * @param receiverFinalBalance   交易后接收方的最终余额。
     * @param containerServerID      签署此确认记录的服务器 ID (公钥)。
     * @param feeAmount              系统数据通常没有费用，此处可设为 0。
     * @param signature              容器服务器对 Payload Body 的签名。
     */
    public BalanceConfirmation(
            byte[] transactionHash,
            long senderFinalBalance,
            long receiverFinalBalance,
            byte[] containerServerID,
            long feeAmount,
            byte[] signature) {

        // 调用父类构造函数，设置 TypeID = 0x02 (DataRecord)
        super(ChainDataType.DATA_RECORD.typeId, feeAmount, containerServerID, signature);

        if (transactionHash == null || transactionHash.length == 0) {
            throw new IllegalArgumentException("Transaction Hash must be provided.");
        }

        this.transactionHash = transactionHash;
        this.senderFinalBalance = senderFinalBalance;
        this.receiverFinalBalance = receiverFinalBalance;
        this.containerServerID = containerServerID;
    }

    public static BalanceConfirmation parseFrom(byte[] fullDataBytes) throws IOException {
        // [TODO: 实现细节] 需要实现完整的 Header 和 Payload Body 的反序列化逻辑
        // 重点是：确保 toPubkey, amount, assetId, memo 的读取顺序和长度与 getPayloadBody() 严格一致。
        throw new UnsupportedOperationException("Transaction Deserialization TBD.");
    }

    // ====================== 核心序列化与解析 ======================

    /**
     * 【核心实现】定义 Payload Body 的写入顺序和结构。
     * 写入顺序即为确定性顺序。
     */
    @Override
    protected byte[] getPayloadBody() throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(baos)) {

            // 1. 写入 SubType (0x01)
            dos.writeByte(SUB_TYPE_BALANCE_CONFIRMATION);
            // 2. 写入被确认交易的 Hash
            dos.write(transactionHash);
            // 3. 写入最终余额
            dos.writeLong(senderFinalBalance);
            dos.writeLong(receiverFinalBalance);
            // 4. 写入签署服务器 ID
            dos.write(containerServerID);

            dos.flush();
            return baos.toByteArray();
        }
    }

    // ====================== 可视化方法 (标准 3) ======================

    @Override
    public String toAuditString() {
        return String.format("BalanceConf [TxHash=%s..., SenderFinal=%d, ReceiverFinal=%d]",
                Hex.toHexString(this.transactionHash).substring(0, 10),
                this.senderFinalBalance,
                this.receiverFinalBalance);
    }

    @Override
    public String toJSON() {
        // 由于字段较多，我们使用更清晰的 JSON 格式
        return String.format(
                """
                {
                  "typeId": "%s",
                  "subType": "%s",
                  "timestamp": %d,
                  "transactionHash": "%s",
                  "senderFinalBalance": %d,
                  "receiverFinalBalance": %d,
                  "signerServerID": "%s",
                  "feeAmount": %d
                }
                """,
                Hex.toHexString(new byte[]{this.typeId}),
                Hex.toHexString(new byte[]{SUB_TYPE_BALANCE_CONFIRMATION}),
                this.timestamp,
                Hex.toHexString(this.transactionHash),
                this.senderFinalBalance,
                this.receiverFinalBalance,
                Hex.toHexString(this.senderPubKey), // 父类的 senderPubKey 实际为签署者
                this.feeAmount
        );
    }

    @Override
    public ChainDataType getDataType() {
        return null;
    }
}