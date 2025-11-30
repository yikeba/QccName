package org.que.protocol;

import com.alibaba.fastjson2.JSON;

/**
 * 通讯层最小单元：客户端 -> 节点
 * 只负责传输：publicKey / payload / signature
 * 不含 address，address 由节点通过 publicKey 计算。
 */
public class QubePacket {
    // 客户端 Dilithium 公钥（建议用 HEX 或 Base64，和你 QubeSigner 保持一致）
    public String publicKey;
    // 客户端签名（HEX 字符串）
    public String signature;
    // 业务 JSON（就是 TransactionData/EntityData/RuleData 的 JSON）
    public String payloadJson;
    // 一些附加信息（可选）
    public long clientTime;
    public long nonce;
    public String toJson() {
        return JSON.toJSONString(this);
    }
    public static QubePacket fromJson(String json) {
        return JSON.parseObject(json, QubePacket.class);
    }
}
