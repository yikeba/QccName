package org.example.wallet;

import org.bouncycastle.pqc.crypto.crystals.dilithium.*;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.MessageDigest;
//改造钱包生成类，作为开源演示

public class QubeWallet {

    private static final SecureRandom random = new SecureRandom();
    private static final char[] BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();

    public static class Wallet {
        public final String address;       // Q开头Base58地址
        public final String privateKeyHex;
        public final String publicKeyHex;

        public final DilithiumPrivateKeyParameters privateKeyParameters;

        Wallet(String address, String privateKey, String publicKey,DilithiumPrivateKeyParameters privateKeyParameters) {
            this.address = address;
            this.privateKeyHex = privateKey;
            this.publicKeyHex = publicKey;
            this.privateKeyParameters=privateKeyParameters;

        }
    }

    public static Wallet QubeWallet() {
        DilithiumKeyPairGenerator generator = new DilithiumKeyPairGenerator();
        generator.init(new DilithiumKeyGenerationParameters(random, DilithiumParameters.dilithium5));
        var kp = generator.generateKeyPair();

        DilithiumPublicKeyParameters pubKey = (DilithiumPublicKeyParameters) kp.getPublic();
        DilithiumPrivateKeyParameters privKey = (DilithiumPrivateKeyParameters) kp.getPrivate();
        System.out.println("你真正使用的参数是: " + privKey.getParameters().getName());
        System.out.println("私钥编码长度: " + privKey.getEncoded().length);
        System.out.println("参数名: " + privKey.getParameters().getName());

        String privHex= Hex.toHexString(getRawPrivateKeyBytes(privKey));  //私钥转换方式，千万不要修改，目前测试 ok
        String pubHex = Hex.toHexString(pubKey.getEncoded());

        //byte[] pubBytes = Hex.decode(pubHex);
        byte[] sha256 = sha256(pubKey.getEncoded());
        byte[] hash160 = ripemd160(sha256);

        byte[] versioned = new byte[21];
        versioned[0] = 0x51; // QubeChain版本字节
        System.arraycopy(hash160, 0, versioned, 1, 20);

        byte[] checksum = sha256(sha256(versioned));
        byte[] binaryAddr = new byte[25];
        System.arraycopy(versioned, 0, binaryAddr, 0, 21);
        System.arraycopy(checksum, 0, binaryAddr, 21, 4);
        String base58 = base58Encode(binaryAddr);
        String address = "Q" + base58;        // 可选 Q 前缀
        System.out.println("抗量子钱包生成成功！");
        System.out.println("公钥匙长度: " + pubHex.length() + ")字节长度:"+pubKey.getEncoded().length);
        System.out.println("地址: " + address + " (长度: " + address.length() + ")");
        System.out.println("私钥长度: " + privHex.length() + "... (测试阶段打印，上线必须加密私钥长度:)"+ privKey.getEncoded().length);
        return new Wallet(address, privHex, pubHex,privKey);
    }

    public static byte[] getRawPrivateKeyBytes(DilithiumPrivateKeyParameters privKey) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            baos.write(privKey.getRho());
            baos.write(privKey.getK());
            baos.write(privKey.getTr());
            baos.write(privKey.getS1());
            baos.write(privKey.getS2());
            baos.write(privKey.getT0());
            baos.write(privKey.getT1());
            byte[] rawKey = baos.toByteArray();
            System.out.println("【正确的原始私钥长度】: " + rawKey.length);
            return rawKey; // 存储这个 byte[] 的 Hex 串
        } catch (IOException e) {
            throw new RuntimeException("Failed to concatenate Dilithium key components.", e);
        }
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