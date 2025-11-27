package org.que.core.queData;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.annotation.JSONField;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.que.crypto.QubeSigner;

/**
 * 交易数据（Transaction）
 */
public class TransactionData extends QueBaseData {

    private static final String TYPE = "transaction";
    private static final int MEMO_MAX_LEN = 30;

    // ===== 固定字段顺序（用于 JSON → Byte 协议） =====

    @JSONField(ordinal  = 5, name = "from")
    public String from;

    @JSONField(ordinal  = 6, name = "to")
    public String to;

    @JSONField(ordinal  = 7, name = "amount")
    public int amount;

    @JSONField(ordinal  = 8, name = "memo")
    public String memo;

    @JSONField(ordinal  = 9, name = "publicKey")
    public String publicKey;

    @JSONField(ordinal  = 10, name = "signature")
    public String signature;

    // ===== 构造 =====
    public TransactionData(String contractAddress) {
        initBaseFields(contractAddress);
    }

    @Override
    public String getType() {
        return TYPE;
    }

    private void checkMemo() {
        if (memo == null) return;
        if (memo.length() > MEMO_MAX_LEN) {
            throw new IllegalArgumentException("Transaction memo 最大长度为 "
                    + MEMO_MAX_LEN + " 字符，当前=" + memo.length());
        }
    }

    @Override
    public String getSignPayload() {
        checkMemo();
        return id + "|" + contractAddress + "|" + from + "|" + to + "|" + amount + "|" +
                (memo == null ? "" : memo);
    }

    public void sign(DilithiumPrivateKeyParameters privKey) {
        this.signature = QubeSigner.sign(getSignPayload(), privKey);
    }

    public boolean verify() {
        return QubeSigner.verify(
                getSignPayload(),
                signature,
                publicKey
        );
    }

    public double getFee() {
        double memoCost = (memo == null || memo.isEmpty()) ? 0.0 : 0.01;
        return memoCost;
    }

    @Override
    public String toString() {
        return "TransactionData{" +
                "id='" + id + '\'' +
                ", contractAddress='" + contractAddress + '\'' +
                ", from='" + from + '\'' +
                ", to='" + to + '\'' +
                ", amount=" + amount +
                ", memo='" + memo + '\'' +
                ", publicKey='" + publicKey + '\'' +
                ", signature='" + signature + '\'' +
                ", timestamp=" + timestamp +
                ", fee=" + getFee() +
                '}';
    }

    public String toJsonString() {
        return JSON.toJSONString(this);
    }
}
