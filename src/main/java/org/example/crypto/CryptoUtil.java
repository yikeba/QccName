package org.example.crypto;

import java.security.MessageDigest;
//区块，容器间数据哈希工具--可以上线使用

public class CryptoUtil {
    public static byte[] sha256(byte[]... inputs) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (byte[] input : inputs) {
                digest.update(input);
            }
            return digest.digest();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] sha256(byte[] input, int offset, int length) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(input, offset, length);
            return digest.digest();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}