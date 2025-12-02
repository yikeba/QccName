package org.que.protocol;

import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.que.core.queData.QueBaseData;
import org.que.core.queData.QubeDataBaseFactory;
import org.que.wallet.WalletSigner;
import org.que.wallet.QubeWallet;
import org.que.wallet.WalletSource;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * 新版 QubeChain 通讯协议（客户端<->节点）v2
 *
 * 作用：
 *     QueBaseData  <->  QubePacket
 *
 * 特点：
 *     ✔ 不再依赖 QueBaseData 中的签名字段
 *     ✔ 不再传递 rawPk
 *     ✔ publicKeyHex 是 DER 格式，兼容所有 Dilithium 实现
 *     ✔ 签名只针对 payloadJson
 *     ✔ address 由服务器端根据 rawPk 自动生成
 */
public class QubeDataProtocol {

    private static final SecureRandom RANDOM = new SecureRandom();

    // ================================================================
    //  1. 客户端编码：QueBaseData -> QubePacket
    // ================================================================
    public static QubePacket encodeData(
            QueBaseData data,
            DilithiumPrivateKeyParameters privKey,
            String publicKeyHex
    ) {

        // -------- 1. JSON 序列化业务数据 --------
        String payloadJson = QubeDataBaseFactory.toJson(data);

        // -------- 2. Dilithium 签名 --------
        String signature = WalletSigner.sign(payloadJson, privKey);

        // -------- 3. 封装传输包 --------
        QubePacket packet = new QubePacket();
        packet.payloadJson = payloadJson;
        packet.signature = signature;
        packet.publicKey = publicKeyHex;
        packet.clientTime = System.currentTimeMillis();
        packet.nonce = RANDOM.nextLong();

        return packet;
    }


    // ================================================================
    //  2. 服务端解码：QubePacket -> QueBaseData（自动验签）
    // ================================================================
    public static QueBaseData decodeData(QubePacket packet) {

        try {
            // -------- 1. 解析 DER 公钥 --------
            byte[] pubBytes = Hex.decode(packet.publicKey);
            DilithiumPublicKeyParameters pubKey =
                    new DilithiumPublicKeyParameters(DilithiumParameters.dilithium5, pubBytes);
            // -------- 2. 验证签名 --------
            boolean ok = WalletSigner.verify(
                    packet.payloadJson,
                    packet.signature,
                    pubKey
            );

            if (!ok) {
                throw new IllegalStateException("签名验证失败");
            }

            // -------- 3. 解析 payloadJson（自动识别三大数据类型） --------
            QueBaseData data = QubeDataBaseFactory.fromJson(packet.payloadJson);

            // -------- 4. 自动推导 from 地址 --------
            byte[] rawPk = QubeWallet.getRawPublicKey(pubKey);
            String address = QubeWallet.generateAddress(rawPk);
            data.from = address;   // 强制覆盖 data.from

            return data;

        } catch (Exception e) {
            throw new IllegalStateException("QubeDataProtocol decodeData 失败: " + e.getMessage(), e);
        }
    }
}
