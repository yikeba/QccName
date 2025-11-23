package org.example.crypto;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.crystals.dilithium.*;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

//抗量子签名，验证--可以商用
public class QubeSigner {

    // 使用 Dilithium5 参数，提供最高安全等级
    private static final DilithiumParameters PARAMS = DilithiumParameters.dilithium5;

    // 生成密钥对
    public static DilithiumKeyPair generateKeyPair() {
        DilithiumKeyGenerationParameters params =
                new DilithiumKeyGenerationParameters(new SecureRandom(), PARAMS);

        DilithiumKeyPairGenerator generator = new DilithiumKeyPairGenerator();
        generator.init(params);

        AsymmetricCipherKeyPair kp = generator.generateKeyPair();

        DilithiumPrivateKeyParameters priv = (DilithiumPrivateKeyParameters) kp.getPrivate();
        DilithiumPublicKeyParameters pub = (DilithiumPublicKeyParameters) kp.getPublic();

        return new DilithiumKeyPair(
                Hex.toHexString(priv.getEncoded()),
                Hex.toHexString(pub.getEncoded())
        );
    }

    // 签名（终极能跑版！！！直接用内存私钥对象）
    public static String sign(String message, DilithiumPrivateKeyParameters privateKey) {
        DilithiumSigner signer = new DilithiumSigner();
        signer.init(true, privateKey);  // true = 签名模式
        byte[] signature = signer.generateSignature(message.getBytes());
        return Hex.toHexString(signature);
    }

    // 客户用这个！！！从Base64私钥签名
    public static String sign(String message, String privateKey)  {
        //byte[] privEncoded = Base64.getDecoder().decode(privateKeyBase64);
        //byte[] privEncoded =DilithiumKeyRestorer.restoreRawPrivateKey(privateKey);

        //System.out.println("解码后的私钥字节数组长度: " + privEncoded.length);

        // 直接用字节数组
        // PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privEncoded);
        DilithiumPrivateKeyParameters privKey =
               // (DilithiumPrivateKeyParameters) PrivateKeyFactory.createKey(pkInfo);
        DilithiumKeyRestorer.restoreRawPrivateKey(privateKey);
        return sign(message,privKey);
    }

    // 验证
    public static boolean verify(String message, String signatureHex, String publicKeyHex) {
        byte[] pubBytes = Hex.decode(publicKeyHex);
        // 【关键修改】：使用构造函数从原始字节还原公钥，而不是 getInstance
        DilithiumPublicKeyParameters pubKey = new DilithiumPublicKeyParameters(PARAMS, pubBytes);
        DilithiumSigner verifier = new DilithiumSigner();
        verifier.init(false, pubKey);
        return verifier.verifySignature(
                message.getBytes(),
                Hex.decode(signatureHex)
        );
    }

    // ==================== 支持原始公钥字节的 verify（推荐！） ====================
    public static boolean verifyRaw(byte[] message, byte[] signature, byte[] publicKeyRawBytes) {
        if (publicKeyRawBytes.length != 1952) { // Dilithium5 公钥固定1952字节
            throw new IllegalArgumentException("Dilithium5公钥必须1952字节，实际: " + publicKeyRawBytes.length);
        }
        if (signature.length < 2400 || signature.length > 2600) {
            throw new IllegalArgumentException("签名长度异常: " + signature.length);
        }

        try {
            // 关键：直接用原始字节构造！BouncyCastle 内部会自动解析 rho + t1
            DilithiumPublicKeyParameters pubKey = new DilithiumPublicKeyParameters(PARAMS, publicKeyRawBytes);

            DilithiumSigner verifier = new DilithiumSigner();
            verifier.init(false, pubKey);
            return verifier.verifySignature(message, signature);

        } catch (Exception e) {
            System.err.println("Dilithium验证失败: " + e.getMessage());
            return false;
        }
    }

    // 兼容你之前可能用到的 String 版（可选）
    public static boolean verifyRaw(byte[] message, byte[] signature, String publicKeyHex) {
        return verifyRaw(message, signature, Hex.decode(publicKeyHex));
    }

    // 持有 Hex 格式密钥
    public static class DilithiumKeyPair {
        public final String privateKeyHex;
        public final String publicKeyHex;

        public DilithiumKeyPair(String priv, String pub) {
            this.privateKeyHex = priv;
            this.publicKeyHex = pub;
        }
    }
}



// 假设您已将正确的 DilithiumParameters 设为静态常量
 class DilithiumKeyRestorer {

    // 您的环境特有的组件长度常量
    private static final int RHO_LEN = 32;
    private static final int K_LEN = 32;
    private static final int TR_LEN = 64;
    private static final int S1_LEN = 672;
    private static final int S2_LEN = 768;
    private static final int T0_LEN = 3328;
    private static final int T1_LEN = 2560;

    // 假设您的 QubeChain 使用 Dilithium5 (或对应的自定义参数)
    private static final DilithiumParameters QUBE_DILITHIUM_PARAMS = DilithiumParameters.dilithium5;

    /**
     * 【Dilithium 私钥还原】
     * 从 Hex 编码的原始字节数组 (7456 字节) 中精确还原私钥对象。
     * * @param privateKeyHex 7456 字节原始私钥的 Hex 编码字符串。
     * @return 可用的 DilithiumPrivateKeyParameters 对象。
     */
    public static DilithiumPrivateKeyParameters restoreRawPrivateKey(String privateKeyHex) {

        // 1. 解码 Hex 得到 7456 字节的原始私钥
        byte[] rawKeyBytes = Hex.decode(privateKeyHex);

        if (rawKeyBytes.length != 7456) {
            throw new IllegalArgumentException("Raw key length is incorrect. Expected 7456 bytes, got " + rawKeyBytes.length);
        }
        // 2. 使用 ByteBuffer 或偏移量进行精确分割
        ByteBuffer buffer = ByteBuffer.wrap(rawKeyBytes);

        byte[] rho = extractBytes(buffer, RHO_LEN);
        byte[] k = extractBytes(buffer, K_LEN);
        byte[] tr = extractBytes(buffer, TR_LEN);
        byte[] s1 = extractBytes(buffer, S1_LEN);
        byte[] s2 = extractBytes(buffer, S2_LEN);
        byte[] t0 = extractBytes(buffer, T0_LEN);
        byte[] t1 = extractBytes(buffer, T1_LEN); // 剩余部分

        // 3. 使用七参数构造函数还原对象
        return new DilithiumPrivateKeyParameters(
                QUBE_DILITHIUM_PARAMS, rho, k, tr, s1, s2, t0, t1);
    }

    /**
     * 辅助方法：从 ByteBuffer 中提取指定长度的字节数组。
     */
    private static byte[] extractBytes(ByteBuffer buffer, int length) {
        byte[] bytes = new byte[length];
        buffer.get(bytes);
        return bytes;
    }
}
