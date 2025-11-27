package org.que.core.queData;

import org.que.crypto.QubeSigner;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;

/**
 * 实体数据（Entity）
 * 用于存储任意业务对象，例如：商品、用户资料、资产信息等
 */
public class EntityData extends QueBaseData {

    private static final String TYPE = "entity";

    public String owner;        // 实体所属的钱包（Qxxxx）
    public String content;      // 实体内容（JSON 字符串或明文或加密数据）
    public String publicKey;    // 所有者的公钥
    public String signature;    // 对 payload 的签名

    public EntityData(String contractAddress) {
        initBaseFields(contractAddress); // 统一生成 id、timestamp
    }

    @Override
    public String getType() {
        return TYPE;
    }

    /**
     * 签名专用内容（确定性）
     * 实体类的签名必须固定格式
     */
    @Override
    public String getSignPayload() {
        return id + "|" + contractAddress + "|" + owner + "|" + content;
    }

    /**
     * 使用 owner's 私钥签名
     */
    public void sign(DilithiumPrivateKeyParameters privKey) {
        this.signature = QubeSigner.sign(getSignPayload(), privKey);
    }

    /**
     * 使用 owner's 公钥验证签名
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

}