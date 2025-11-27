package org.que.protocol;

import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.que.core.queData.QueBaseData;
import org.que.core.queData.QubeDataBaseFactory;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * Qube 数据协议编解码工具：
 * QueBaseData <-> QubePacket
 */
public class QubeDataProtocol {

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * 客户端：把任意 QueBaseData 封装成 QubePacket，并完成签名
     *
     * @param data           三大数据之一：TransactionData / EntityData / RuleData
     * @param privKey        抗量子私钥
     * @param publicKeyBytes 抗量子公钥字节（和钱包地址对应）
     */
    public static QubePacket encodeData(QueBaseData data,
                                        DilithiumPrivateKeyParameters privKey,
                                        byte[] publicKeyBytes) {

        // 1. 对数据对象做 JSON 序列化
        String json = QubeDataBaseFactory.toJson(data);
        byte[] payload = json.getBytes(StandardCharsets.UTF_8);

        long clientTime = System.currentTimeMillis();
        long nonce = RANDOM.nextLong();

        // 2. 构建协议包
        QubePacket packet = new QubePacket(publicKeyBytes, clientTime, nonce, payload);

        // 3. 用客户端钱包私钥签名
        packet.sign(privKey);

        return packet;
    }

    /**
     * 服务端：从 QubePacket 中解析出 QueBaseData
     *
     * @throws IllegalStateException 如果签名验证失败
     */
    public static QueBaseData decodeData(QubePacket packet) {
        // 1. 验签（非常关键）
        if (!packet.verify()) {
            throw new IllegalStateException("QubePacket 签名验证失败，拒绝处理");
        }

        // 2. 解析 payload JSON
        String json = new String(packet.payload, StandardCharsets.UTF_8);

        // 3. 使用通用工厂还原三大数据类型
        return QubeDataBaseFactory.fromJson(json);
    }
}
