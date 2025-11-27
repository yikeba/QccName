package org.que.core.queData;


import org.que.crypto.QubeSigner;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;

/**
 * 交易数据（Transaction）
 * 金额统一采用 int（两位小数：100 = 1.00）
 */
public class TransactionData extends QueBaseData {

    private static final String TYPE = "transaction";

    public String from;        // Qxxxx 发送方地址
    public String to;          // Qxxxx 接收方地址
    public int amount;         // 金额（最小单位 ×100，例如 1.00 = 100）

    public String publicKey;   // 发送方公钥 HEX
    public String signature;   // 对 payload 的签名

    public TransactionData(String contractAddress) {
        initBaseFields(contractAddress);
    }

    @Override
    public String getType() {
        return TYPE;
    }

    /**
     * 签名专用字符串（确定性、统一格式）
     * 不可随意改变结构！
     */
    @Override
    public String getSignPayload() {
        return id + "|" + contractAddress + "|" + from + "|" + to + "|" + amount;

    }

    /**
     * 用发送方私钥签名
     */
    public void sign(DilithiumPrivateKeyParameters privKey) {
        this.signature = QubeSigner.sign(getSignPayload(), privKey);
    }

    /**
     * 使用发送方公钥验证签名
     */
    public boolean verify() {
        return QubeSigner.verify(
                getSignPayload(),
                signature,
                publicKey
        );
    }

    @Override
    public String toString() {
        return "TransactionData{" +
                "id='" + id + '\'' +
                ", contractAddress='" + contractAddress + '\'' +
                ", from='" + from + '\'' +
                ", to='" + to + '\'' +
                ", amount=" + amount +
                ", publicKey='" + publicKey + '\'' +
                ", signature='" + signature + '\'' +
                ", timestamp=" + timestamp +
                '}';
    }

}

