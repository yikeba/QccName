package org.que.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.crystals.dilithium.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.security.Security;

public class QubeKeyRawTest {

    private static final SecureRandom random = new SecureRandom();

    //================ 1. 生成 Dilithium5 密钥对（正确类型） ==================
    private static AsymmetricCipherKeyPair generateKeyPair() {
        DilithiumKeyPairGenerator gen = new DilithiumKeyPairGenerator();
        gen.init(new DilithiumKeyGenerationParameters(random, DilithiumParameters.dilithium5));
        return gen.generateKeyPair();   // ⭐ 返回 AsymmetricCipherKeyPair
    }

    //================ 2. 获取原始公钥（rho + t1） ==================
    private static byte[] getRawPublicKeyBytes(DilithiumPublicKeyParameters pub) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            baos.write(pub.getRho());   // 32 bytes
            baos.write(pub.getT1());    // 2560 bytes
            return baos.toByteArray();  // = 2592 bytes
        } catch (Exception e) {
            throw new RuntimeException("Raw PublicKey extract failed", e);
        }
    }

    //================ SHA256 =================
    private static byte[] sha256(byte[] in) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(in);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    //================ RIPEMD160 =================
    private static byte[] ripemd160(byte[] in) {
        return new org.bouncycastle.jcajce.provider.digest.RIPEMD160.Digest().digest(in);
    }

    //================ Base58 =================
    private static final char[] BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();

    private static String base58Encode(byte[] input) {
        java.math.BigInteger num = new java.math.BigInteger(1, input);
        StringBuilder sb = new StringBuilder();
        while (num.compareTo(java.math.BigInteger.ZERO) > 0) {
            int r = num.mod(java.math.BigInteger.valueOf(58)).intValue();
            sb.insert(0, BASE58[r]);
            num = num.divide(java.math.BigInteger.valueOf(58));
        }
        return sb.toString();
    }

    //================ 3. raw 公钥 → 地址 =================
    private static String generateAddress(byte[] rawPk) {
        byte[] step1 = sha256(rawPk);
        byte[] step2 = ripemd160(step1);

        byte[] versioned = new byte[21];
        versioned[0] = 0x51; // 'Q'
        System.arraycopy(step2, 0, versioned, 1, 20);

        byte[] checksum = sha256(sha256(versioned));

        byte[] full = new byte[25];
        System.arraycopy(versioned, 0, full, 0, 21);
        System.arraycopy(checksum, 0, full, 21, 4);

        return "Q" + base58Encode(full);
    }

    //================ 签名 =================
    private static String sign(String msg, DilithiumPrivateKeyParameters priv) {
        DilithiumSigner signer = new DilithiumSigner();
        signer.init(true, priv);
        byte[] sig = signer.generateSignature(msg.getBytes(StandardCharsets.UTF_8));
        return Hex.toHexString(sig);
    }

    //================ 验签 =================
    private static boolean verify(String msg, String sigHex, DilithiumPublicKeyParameters pub) {
        DilithiumSigner verifier = new DilithiumSigner();
        verifier.init(false, pub);
        return verifier.verifySignature(
                msg.getBytes(StandardCharsets.UTF_8),
                Hex.decode(sigHex)
        );
    }

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            System.out.println(">>> [DemoTest Static Init] BouncyCastle Provider 强制注册成功！");
        }
    }


    //================ 主测试（100条） =================
    public static void main(String[] args) {

        int total = 100;
        int pass = 0;

        System.out.println("=== QubeChain RawPK Test (rho+t1) Final ===");

        for (int i = 0; i < total; i++) {

            // ⭐ 正确密钥对类型
            AsymmetricCipherKeyPair kp = generateKeyPair();
            DilithiumPublicKeyParameters pub = (DilithiumPublicKeyParameters) kp.getPublic();
            DilithiumPrivateKeyParameters pri = (DilithiumPrivateKeyParameters) kp.getPrivate();

            byte[] rawPk = getRawPublicKeyBytes(pub);
            String addr = generateAddress(rawPk);

            String msg = "hello_" + System.nanoTime();
            String sig = sign(msg, pri);

            boolean ok = verify(msg, sig, pub);
            if (ok) pass++;

            System.out.println("[" + i + "] rawPkLen=" + rawPk.length
                    + ", address=" + addr
                    + ", verify=" + ok);
        }

        System.out.println("\n==============================");
        System.out.println("最终结果: " + pass + " / " + total + " 成功");
        System.out.println("==============================");

        if (pass == total) {
            System.out.println("🎉🎉🎉 100条测试全部成功，可以安全升级原始公钥地址算法！");
        } else {
            System.out.println("❌ 存在失败，不可迁移！");
        }
    }
}
