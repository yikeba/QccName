package org.que.util;

import java.math.BigInteger;
import java.util.UUID;

public class ToolsUtil {

    private static final char[] BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();

    public static String getUUID(){
        return UUID.randomUUID().toString().replace("-", "");
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
