package org.que.core.queData;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.annotation.JSONField;   // 必须导入！
import org.que.crypto.QubeSigner;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;

/**
 * 规则数据（Rule）
 * 用于定义系统级规则、链参数、权限规则等。
 */
public class RuleData extends QueBaseData {

    private static final String TYPE = "rule";

    @JSONField(ordinal = 5)  public String ruleCode;      // 第5位
    @JSONField(ordinal = 6)  public String description;   // 第6位
    @JSONField(ordinal = 7)  public String publicKey;     // 第7位
    @JSONField(ordinal = 8)  public String signature;    // 第8位

    public RuleData(String contractAddress) {
        initBaseFields(contractAddress);
    }

    @Override
    public String getType() {
        return TYPE;
    }

    /**
     * 规则数据的固定签名内容（必须保持确定性）
     */
    @Override
    public String getSignPayload() {
        return id + "|" + contractAddress + "|" + ruleCode + "|" + description;
    }

    public void sign(DilithiumPrivateKeyParameters privKey) {
        this.signature = QubeSigner.sign(getSignPayload(), privKey);
    }

    public boolean verify() {
        return QubeSigner.verify(getSignPayload(), signature, publicKey);
    }

    @Override
    public String toString() {
        return "RuleData{" +
                "id='" + id + '\'' +
                ", contractAddress='" + contractAddress + '\'' +
                ", ruleCode='" + ruleCode + '\'' +
                ", description='" + description + '\'' +
                ", publicKey='" + publicKey + '\'' +
                ", signature='" + signature + '\'' +
                ", timestamp=" + timestamp +
                '}';
    }
    public String toJsonString() {
        return JSON.toJSONString(this);
    }
}