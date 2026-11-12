package qcc.qccwallet;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * ════════════════════════════════════════════════════════
 * 多签地址定长性验证 —— 真实生成路径版
 *
 * 与上一版隔离测试的区别：这次直接调用
 * MultiSigAddrTool.deriveMultiAddrFromPubKeys()，走完整业务路径
 * （canonicalEncode 二进制编码、pubkey 排序、ChainIdentity 注入、
 *  RIPEMD160(SHA3-256(canonical)) 真实哈希链），不再用随机字节
 * 模拟 hash20 来源。
 *
 * 每次迭代随机生成 2~7 个签名方公钥（真实 ML-DSA-87 公钥长度
 * 2592 字节 = 5184 hex 字符），threshold 随机取 [1, n]。
 *
 * 前提：项目里 ChainIdentity.current() 必须已正确初始化
 * （本测试不 mock 链身份配置，直接用项目现有配置）。
 *
 * 用法：放进 qcc.service 包下直接运行 main()
 * ════════════════════════════════════════════════════════
 */
public class MultiSigAddressGenerationTest {

    private static final int SAMPLE_COUNT = 100_000;
    private static final int PUBKEY_BYTE_LEN = 2592; // ML-DSA-87 公钥长度

    public static void main(String[] args) {
        SecureRandom random = new SecureRandom();
        Map<Integer, Integer> lengthHistogram = new TreeMap<>();
        Map<Character, Integer> firstCharHistogram = new TreeMap<>();
        int nullResults = 0;
        int checksumFailures = 0;
        long start = System.currentTimeMillis();

        for (int i = 0; i < SAMPLE_COUNT; i++) {
            int n = 2 + random.nextInt(6); // 2~7 个签名方
            int threshold = 1 + random.nextInt(n); // threshold ∈ [1, n]

            List<String> ownerPubKeyHex = new ArrayList<>();
            for (int j = 0; j < n; j++) {
                ownerPubKeyHex.add(randomHex(random, PUBKEY_BYTE_LEN));
            }

            String address = MultiSigAddrTool.deriveMultiAddrFromPubKeys(ownerPubKeyHex, threshold);

            if (address == null) {
                nullResults++;
                continue;
            }

            lengthHistogram.merge(address.length(), 1, Integer::sum);
            firstCharHistogram.merge(address.charAt(0), 1, Integer::sum);

            if (!MultiSigAddrTool.isValidMultiSigAddress(address)) {
                checksumFailures++;
            }
        }

        long elapsed = System.currentTimeMillis() - start;

        System.out.println("=== 多签地址真实生成路径验证 (deriveMultiAddrFromPubKeys, version=0x33) ===");
        System.out.println("样本数: " + SAMPLE_COUNT + "   耗时: " + elapsed + "ms");
        System.out.println("生成失败(null)次数: " + nullResults);
        System.out.println();

        System.out.println("-- 长度分布 --");
        for (Map.Entry<Integer, Integer> entry : lengthHistogram.entrySet()) {
            double pct = entry.getValue() * 100.0 / SAMPLE_COUNT;
            System.out.printf("  长度 %d 字符: %d 次 (%.4f%%)%n", entry.getKey(), entry.getValue(), pct);
        }

        System.out.println();
        System.out.println("-- 首字符分布 --");
        for (Map.Entry<Character, Integer> entry : firstCharHistogram.entrySet()) {
            double pct = entry.getValue() * 100.0 / SAMPLE_COUNT;
            System.out.printf("  首字符 \"%s\": %d 次 (%.4f%%)%n", entry.getKey(), entry.getValue(), pct);
        }

        System.out.println();
        boolean lengthOk = lengthHistogram.size() == 1 && lengthHistogram.containsKey(34);
        boolean firstCharOk = firstCharHistogram.size() == 1 && firstCharHistogram.containsKey('M');

        System.out.println(nullResults == 0
                ? "✅ 未出现生成失败(null)的情况"
                : "❌ 有 " + nullResults + " 次生成返回 null，需要检查输入构造逻辑");
        System.out.println(lengthOk ? "✅ 长度恒为 34 字符" : "❌ 出现非 34 字符地址");
        System.out.println(firstCharOk ? "✅ 首字符恒为 'M'" : "❌ 出现非 'M' 开头地址");
        System.out.println(checksumFailures == 0
                ? "✅ isValidMultiSigAddress 校验全部通过"
                : "❌ 有 " + checksumFailures + " 个地址未通过 isValidMultiSigAddress 校验");
    }

    private static String randomHex(SecureRandom random, int byteLen) {
        byte[] bytes = new byte[byteLen];
        random.nextBytes(bytes);
        StringBuilder sb = new StringBuilder(byteLen * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
