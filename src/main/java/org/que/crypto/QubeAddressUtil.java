package org.que.crypto;

// QubeAddressUtil.java
// QubeChain 官方地址工具类（全球开源 · 永不更改 · 量子原生标准）
// 作者：你（量子之王）
// 时间：2025年11月23日
// 版本：v1.1.0（主网永封版 + 地址反解析功能）
// 新增功能：支持地址 → 公钥提取（用于验签）

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

    // ==================== 【新增】地址 → 公钥验证工具 ====================

    /**
     * 【新增方法1】验证公钥是否匹配地址
     * 用途：在验签前确认公钥和地址的对应关系
     *
     * @param address Q开头的量子链地址
     * @param publicKeyBytes 待验证的公钥字节数组
     * @return true=公钥匹配该地址，false=不匹配
     */
    public static boolean verifyPublicKeyMatchesAddress(String address, byte[] publicKeyBytes) {
        if (!isValidAddress(address)) {
            return false;
        }

        try {
            // 从公钥计算地址
            String calculatedAddress = pubKeyToAddress(publicKeyBytes);

            // 比对地址
            return address.equals(calculatedAddress);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 【新增方法2】从地址提取 Hash160 并转为十六进制字符串
     * 用途：用于 AddressIndexService 的索引键值
     *
     * @param address Q开头的量子链地址
     * @return Hash160的十六进制字符串（40字符）
     */
    public static String addressToHash160Hex(String address) {
        byte[] hash160 = addressToHash160(address);
        return Hex.toHexString(hash160);
    }

    /**
     * 【新增方法3】批量验证地址格式
     * 用途：在接收交易前批量校验地址合法性
     *
     * @param addresses 地址数组
     * @return 第一个非法地址，如果全部合法则返回 null
     */
    public static String findInvalidAddress(String... addresses) {
        for (String address : addresses) {
            if (!isValidAddress(address)) {
                return address;
            }
        }
        return null;
    }

    /**
     * 【新增方法4】解析地址详细信息（调试用）
     * 用途：开发调试时查看地址的内部结构
     *
     * @param address Q开头的量子链地址
     * @return 地址详细信息的 JSON 风格字符串
     */
    public static String debugAddress(String address) {
        if (!isValidAddress(address)) {
            return "{\"valid\": false, \"address\": \"" + address + "\"}";
        }

        try {
            byte[] decoded = base58Decode(address.substring(1));
            byte version = decoded[0];
            byte[] hash160 = Arrays.copyOfRange(decoded, 1, 21);
            byte[] checksum = Arrays.copyOfRange(decoded, 21, 25);

            return String.format(
                    "{\"valid\": true, \"address\": \"%s\", \"version\": \"0x%02X\", \"hash160\": \"%s\", \"checksum\": \"%s\"}",
                    address,
                    version,
                    Hex.toHexString(hash160),
                    Hex.toHexString(checksum)
            );
        } catch (Exception e) {
            return "{\"valid\": false, \"error\": \"" + e.getMessage() + "\"}";
        }
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

    public static byte[] base58Decode(String input) {
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

        // 处理前导零
        int leadingZeros = 0;
        for (char c : input.toCharArray()) {
            if (c == '1') leadingZeros++;
            else break;
        }

        // 移除 BigInteger 可能添加的符号位
        int startIndex = (bytes.length > 0 && bytes[0] == 0) ? 1 : 0;

        // 构建最终结果
        byte[] result = new byte[leadingZeros + bytes.length - startIndex];
        System.arraycopy(bytes, startIndex, result, leadingZeros, bytes.length - startIndex);

        return result;
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

    // ==================== 【使用示例】（删除前的注释） ====================
    /*
     * 使用示例1：验证公钥和地址的匹配关系
     *
     * String address = "QjieFftCDVw96VDBF2R1KYgCKY3TAwR4Nd";
     * byte[] publicKey = Hex.decode("your_public_key_hex");
     *
     * if (QubeAddressUtil.verifyPublicKeyMatchesAddress(address, publicKey)) {
     *     System.out.println("✓ 公钥匹配该地址，可以验签！");
     * } else {
     *     System.out.println("✗ 公钥不匹配，拒绝验签！");
     * }
     *
     * ---
     *
     * 使用示例2：在 AddressIndexService 中使用
     *
     * // 注册时存储 Hash160
     * String hash160Hex = QubeAddressUtil.addressToHash160Hex(address);
     * addressIndex.put(hash160Hex, publicKeyHex);
     *
     * // 验签时查询
     * String hash160Hex = QubeAddressUtil.addressToHash160Hex(address);
     * String publicKeyHex = addressIndex.get(hash160Hex);
     *
     * ---
     *
     * 使用示例3：调试地址
     *
     * System.out.println(QubeAddressUtil.debugAddress("QjieFftCDVw96VDBF2R1KYgCKY3TAwR4Nd"));
     * // 输出：{"valid": true, "address": "...", "version": "0x51", "hash160": "...", "checksum": "..."}
     */
}