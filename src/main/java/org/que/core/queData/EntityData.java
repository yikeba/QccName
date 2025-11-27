package org.que.core.queData;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.annotation.JSONField;  // ← 别忘了这个 import！
import org.que.crypto.QubeSigner;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;

/**
 * 实体数据（Entity）
 */
public class EntityData extends QueBaseData {

    private static final String TYPE = "entity";

    @JSONField(ordinal = 5)  public String owner;        // 第5位
    @JSONField(ordinal = 6)  public String content;      // 第6位
    @JSONField(ordinal = 7)  public String publicKey;    // 第7位
    @JSONField(ordinal = 8)  public String signature;   // 第8位

    public EntityData(String contractAddress) {
        initBaseFields(contractAddress);
    }

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public String getSignPayload() {
        return id + "|" + contractAddress + "|" + owner + "|" + content;
    }

    public void sign(DilithiumPrivateKeyParameters privKey) {
        this.signature = QubeSigner.sign(getSignPayload(), privKey);
    }

    public boolean verify() {
        return QubeSigner.verify(getSignPayload(), signature, publicKey);
    }

    @Override
    public String toString() {
        return "EntityData{" +
                "id='" + id + '\'' +
                ", contractAddress='" + contractAddress + '\'' +
                ", owner='" + owner + '\'' +
                ", content='" + content + '\'' +
                ", publicKey='" + publicKey + '\'' +
                ", signature='" + signature + '\'' +
                ", timestamp=" + timestamp +
                '}';
    }

    public String toJsonString() {
        return JSON.toJSONString(this);
    }
}