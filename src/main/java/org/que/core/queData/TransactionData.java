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

    // === 手续费配置：统一 long，单位：nanoQUBE（最小单位） ===
    // 假设：1 QUBE = 1_0000_0000 nanoQUBE（你可以以后统一改）
    private static final long BASE_FEE_NANO       = 0L;          // 基础手续费
    private static final long MEMO_EXTRA_FEE_NANO = 1_000_000L;  // 有 memo 时额外收 0.01 QUBE 就等你以后换算


    // ===== 固定字段顺序（用于 JSON → Byte 协议） =====

    @JSONField(ordinal  = 6, name = "from")
    public String from;

    @JSONField(ordinal  = 7, name = "to")
    public String to;

    @JSONField(ordinal  = 8, name = "amount")
    public long amount;

    @JSONField(ordinal  = 9, name = "memo")
    public String memo;

    @JSONField(ordinal  = 10, name = "publicKey")
    public String publicKey;

    @JSONField(ordinal  = 11, name = "signature")
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

    public long calcFee() {
        long fee = BASE_FEE_NANO;
        if (memo != null && !memo.isEmpty()) {
            fee += MEMO_EXTRA_FEE_NANO;
        }
        return fee;
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

    public long getFee() {
        long fee = BASE_FEE_NANO;
        if (memo != null && !memo.isEmpty()) {
            fee += MEMO_EXTRA_FEE_NANO;
        }
        return fee;
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
