package org.que.util;


import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicInteger;

public class QubeIdUtil {

    // 计数器，用于同一毫秒内的并发去重（0 ~ 999 循环）
    private static final AtomicInteger COUNTER = new AtomicInteger(0);

    // 全局安全随机数（启动一次，长期使用）
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * 生成 QubeID：
     * 13位时间戳(十进制) + 3位计数器(十进制补零) + 16位随机HEX = 32位
     */
    public static String nextId() {
        long now = System.currentTimeMillis();

        // 13位时间戳
        String ts = String.valueOf(now);  // 13 digits

        // 3位计数器，000~999 循环
        int c = COUNTER.getAndUpdate(old -> (old >= 999 ? 0 : old + 1));
        String counterStr = String.format("%03d", c);

        // 16位随机HEX（8字节）
        byte[] randBytes = new byte[8];
        RANDOM.nextBytes(randBytes);
        String randHex = toHex(randBytes);

        // 最终长度：13 + 3 + 16 = 32
        return ts + counterStr + randHex;
    }

    // 简单十六进制工具
    private static String toHex(byte[] bytes) {
        char[] HEX = "0123456789abcdef".toCharArray();
        char[] out = new char[bytes.length * 2];
        int i = 0;
        for (byte b : bytes) {
            int v = b & 0xFF;
            out[i++] = HEX[v >>> 4];
            out[i++] = HEX[v & 0x0F];
        }
        return new String(out);
    }
}

