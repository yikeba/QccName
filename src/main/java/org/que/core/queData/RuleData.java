package org.que.core.queData;


import org.que.crypto.QubeSigner;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;

/**
 * 规则数据（Rule）
 * 用于定义系统级规则、链参数、权限规则等。
 */
public class RuleData extends QueBaseData {

    private static final String TYPE = "rule";

    public String ruleCode;      // 规则编号（唯一）
    public String description;   // 规则描述（明文或JSON）
    public String publicKey;     // 发布者公钥（决定验证签名）
    public String signature;     // 签名

    public RuleData(String contractAddress) {
        initBaseFields(contractAddress); // 初始化 id 和 timestamp
    }

    @Override
    public String getType() {
        return TYPE;
    }

    /**
     * 规则数据的固定签名内容
     * 必须保持确定性
     */
    @Override
    public String getSignPayload() {
        return id +"|"+ contractAddress +"|"+ ruleCode +"|"+ description;

    }

    /**
     * 使用发布者私钥进行签名
     */
    public void sign(DilithiumPrivateKeyParameters privKey) {
        this.signature = QubeSigner.sign(getSignPayload(), privKey);
    }

    /**
     * 使用发布者公钥验证签名
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

}
