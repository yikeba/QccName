package org.que.wallet;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.crystals.dilithium.*;
import org.bouncycastle.util.encoders.Hex;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;



public class QubeWallet {

    private static final SecureRandom random = new SecureRandom();
    private static final char[] BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();

    // ====================1. 生成钱包 ====================
    public static WalletSource generate() {
        DilithiumKeyPairGenerator gen = new DilithiumKeyPairGenerator();
        gen.init(new DilithiumKeyGenerationParameters(random, DilithiumParameters.dilithium5));

        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        DilithiumPublicKeyParameters pub = (DilithiumPublicKeyParameters) kp.getPublic();
        DilithiumPrivateKeyParameters pri = (DilithiumPrivateKeyParameters) kp.getPrivate();

        // 原始公钥（rho + t1）
        byte[] rawPk = getRawPublicKey(pub);
        // 生成地址
        String address = generateAddress(rawPk);
        // 私钥 Hex（raw 结构）
        String privHex = Hex.toHexString(getRawPrivateKey(pri));
        // DER 公钥用于验签
        String pubHex = Hex.toHexString(pub.getEncoded());
        return new WalletSource(address, privHex, pubHex, pri);
    }

    // ====================2. 原始公钥（rho + t1） ====================
    public static byte[] getRawPublicKey(DilithiumPublicKeyParameters pub) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            baos.write(pub.getRho());   // 32 bytes
            baos.write(pub.getT1());    // 2560 bytes
            return baos.toByteArray();  // 2592 bytes
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ====================3. 抽取原始私钥（七段合并） ====================
    public static byte[] getRawPrivateKey(DilithiumPrivateKeyParameters priv) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            baos.write(priv.getRho());
            baos.write(priv.getK());
            baos.write(priv.getTr());
            baos.write(priv.getS1());
            baos.write(priv.getS2());
            baos.write(priv.getT0());
            baos.write(priv.getT1());
            return baos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ====================4. 地址算法（新版主网级） ====================
    public static String generateAddress(byte[] rawPk) {
        byte[] step1 = sha256(rawPk);
        byte[] step2 = ripemd160(step1);

        byte[] versioned = new byte[21];
        versioned[0] = 0x51;  // 'Q'
        System.arraycopy(step2, 0, versioned, 1, 20);

        byte[] checksum = sha256(sha256(versioned));
        byte[] full = new byte[25];

        System.arraycopy(versioned, 0, full, 0, 21);
        System.arraycopy(checksum, 0, full, 21, 4);

        return "Q" + base58Encode(full);
    }


    // 工具方法
    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] ripemd160(byte[] input) {
        try {
            return org.bouncycastle.jcajce.provider.digest.RIPEMD160.Digest.getInstance("RIPEMD160").digest(input);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String base58Encode(byte[] input) {
        // 经典Base58实现（比特币/TRON同款）
        StringBuilder sb = new StringBuilder();
        int zeros = 0;
        for (byte b : input) if (b == 0) zeros++; else break;

        BigInteger num = new BigInteger(1, input);
        while (num.compareTo(BigInteger.ZERO) > 0) {
            int remainder = num.mod(BigInteger.valueOf(58)).intValue();
            sb.insert(0, BASE58[remainder]);
            num = num.divide(BigInteger.valueOf(58));
        }

        for (int i = 0; i < zeros; i++) sb.insert(0, BASE58[0]);
        return sb.toString();
    }


}
