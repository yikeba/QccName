package org.example.crypto;

// QubeAddressUtil.java
// QubeChain 官方地址工具类（全球开源 · 永不更改 · 量子原生标准）
// 作者：你（量子之王）
// 时间：2025年11月23日
// 版本：v1.0.0（主网永封版）

import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;

public final class QubeAddressUtil {

    // ==================== 常量（全球统一，永不修改） ====================
    private static final byte VERSION_BYTE = 0x51;  // QubeChain 主网版本字节 → 决定 Q 开头
    private static final char[] BASE58_ALPHABET =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();

    // ==================== 公钥 → 地址（最硬标准） ====================
    /**
     * 将 Dilithium5 公钥原始字节转换为 Q 开头的标准地址
     * @param publicKeyBytes Dilithium5 公钥原始字节（1952字节）
     * @return Q开头的Base58地址（长度34~35）
     */
    public static String pubKeyToAddress(byte[] publicKeyBytes) {
        if (publicKeyBytes == null || publicKeyBytes.length == 0) {
            throw new IllegalArgumentException("公钥不能为空");
        }

        byte[] sha256 = sha256(publicKeyBytes);
        byte[] ripemd160 = ripemd160(sha256);

        byte[] versioned = new byte[21];
        versioned[0] = VERSION_BYTE;
        System.arraycopy(ripemd160, 0, versioned, 1, 20);

        byte[] checksum = sha256(sha256(versioned));
        byte[] binary = new byte[25];
        System.arraycopy(versioned, 0, binary, 0, 21);
        System.arraycopy(checksum, 0, binary, 21, 4);

        return "Q" + base58Encode(binary).substring(1);
    }

    // ==================== 地址 → Hash160（用于索引） ====================
    /**
     * 从 Q 地址提取 Hash160（用于索引服务器快速查公钥）
     */
    public static byte[] addressToHash160(String address) {
        validateAddress(address);
        byte[] decoded = base58Decode(address.substring(1));
        return Arrays.copyOfRange(decoded, 1, 21); // 去掉版本字节
    }

    // ==================== 地址合法性检查（全球统一校验） ====================
    public static boolean isValidAddress(String address) {
        if (address == null || !address.startsWith("Q") || address.length() < 30 || address.length() > 35) {
            return false;
        }
        try {
            byte[] decoded = base58Decode(address.substring(1));
            if (decoded.length != 25) return false;

            byte[] payload = Arrays.copyOfRange(decoded, 0, 21);
            byte[] checksum = Arrays.copyOfRange(decoded, 21, 25);
            byte[] expected = Arrays.copyOfRange(sha256(sha256(payload)), 0, 4);

            return Arrays.equals(checksum, expected);
        } catch (Exception e) {
            return false;
        }
    }

    // ==================== 内部工具方法（不可外部调用） ====================
    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 unavailable", e);
        }
    }

    private static byte[] ripemd160(byte[] input) {
        try {
            return org.bouncycastle.jcajce.provider.digest.RIPEMD160.Digest.getInstance("RIPEMD160").digest(input);
        } catch (Exception e) {
            throw new RuntimeException("RIPEMD160 unavailable", e);
        }
    }

    private static String base58Encode(byte[] input) {
        if (input.length == 0) return "";

        BigInteger value = new BigInteger(1, input);
        StringBuilder sb = new StringBuilder();

        while (value.compareTo(BigInteger.ZERO) > 0) {
            int remainder = value.mod(BigInteger.valueOf(58)).intValue();
            sb.insert(0, BASE58_ALPHABET[remainder]);
            value = value.divide(BigInteger.valueOf(58));
        }

        // 前导零处理
        for (byte b : input) {
            if (b == 0) {
                sb.insert(0, '1');
            } else {
                break;
            }
        }
        return sb.toString();
    }

    private static byte[] base58Decode(String input) {
        if (input.isEmpty()) return new byte[0];

        BigInteger value = BigInteger.ZERO;
        for (char c : input.toCharArray()) {
            int digit = -1;
            for (int i = 0; i < BASE58_ALPHABET.length; i++) {
                if (BASE58_ALPHABET[i] == c) {
                    digit = i;
                    break;
                }
            }
            if (digit == -1) throw new IllegalArgumentException("Invalid Base58 character: " + c);
            value = value.multiply(BigInteger.valueOf(58)).add(BigInteger.valueOf(digit));
        }

        byte[] bytes = value.toByteArray();
        if (bytes[0] == 0 && input.startsWith("1")) {
            byte[] result = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, result, 0, result.length);
            return result;
        }
        return bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }

    // 地址校验（抛异常版）
    private static void validateAddress(String address) {
        if (!isValidAddress(address)) {
            throw new IllegalArgumentException("无效的QubeChain地址: " + address);
        }
    }

    // 禁止实例化
    private QubeAddressUtil() {
        throw new AssertionError("QubeAddressUtil 不能实例化");
    }
}