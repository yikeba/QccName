package qcc.qccwallet;

import org.bouncycastle.crypto.digests.SHA3Digest;
import qcc.util.Base58;
import java.security.SecureRandom;
import java.util.Map;
import java.util.TreeMap;

/**
 * ════════════════════════════════════════════════════════
 * QCC 地址定长性验证 —— 单签(Q) + 多签(M) 天然34字符方案
 * 一次运行同时验证两套方案：
 *   1) 单签：直接调用真实的 AddressTool.creatAddress()
 *      (version=0x3A，走完整的 SHA3-256(pubkey) -> hash20 流程)
 *   2) 多签：隔离验证 version=0x33 的长度/首字符属性
 *      (不依赖 ChainIdentity/canonicalEncode 等业务逻辑，
 *       只用真实的双重 SHA3-256 驱动随机性，跟长度这个
 *       属性完全无关的部分不参与，跑起来不需要 mock 配置)
 * 用法：放进 qcc.qccwallet 包下直接运行 main()
 * ════════════════════════════════════════════════════════
 */
public class QccAddressLengthTest {

    private static final int SAMPLE_COUNT = 100_000;
    private static final int PUBKEY_BYTE_LEN = 2592; // ML-DSA-87 公钥长度

    // 与 MultiSigAddrTool_34char.java 保持一致
    private static final byte MULTI_VERSION_BYTE = 0x33;

    public static void main(String[] args) {
        System.out.println("========================================================");
        System.out.println("Part 1/2：单签地址 (AddressTool, version=0x3A) 定长性验证");
        System.out.println("========================================================");
        runSingleSigTest();

        System.out.println();
        System.out.println("========================================================");
        System.out.println("Part 2/2：多签地址 (version=0x33) 定长性验证");
        System.out.println("========================================================");
        runMultiSigTest();
    }

    private static void runSingleSigTest() {
        SecureRandom random = new SecureRandom();
        Map<Integer, Integer> lengthHistogram = new TreeMap<>();
        Map<Character, Integer> firstCharHistogram = new TreeMap<>();
        int checksumFailures = 0;
        long start = System.currentTimeMillis();

        for (int i = 0; i < SAMPLE_COUNT; i++) {
            String pubKeyHex = randomHex(random, PUBKEY_BYTE_LEN);
            String address = AddressTool.creatAddress(pubKeyHex);

            lengthHistogram.merge(address.length(), 1, Integer::sum);
            firstCharHistogram.merge(address.charAt(0), 1, Integer::sum);

            if (!AddressTool.isValidAddress(address)) {
                checksumFailures++;
            }
        }

        long elapsed = System.currentTimeMillis() - start;
        System.out.println("样本数: " + SAMPLE_COUNT + "   耗时: " + elapsed + "ms");
        printHistogram("长度", lengthHistogram);
        printCharHistogram("首字符", firstCharHistogram);

        boolean lengthOk = lengthHistogram.size() == 1 && lengthHistogram.containsKey(34);
        boolean firstCharOk = firstCharHistogram.size() == 1 && firstCharHistogram.containsKey('Q');

        System.out.println(lengthOk ? "✅ 长度恒为 34 字符" : "❌ 出现非 34 字符地址");
        System.out.println(firstCharOk ? "✅ 首字符恒为 'Q'" : "❌ 出现非 'Q' 开头地址");
        System.out.println(checksumFailures == 0
                ? "✅ isValidAddress 校验全部通过"
                : "❌ 有 " + checksumFailures + " 个地址未通过 isValidAddress 校验");
    }

    private static void runMultiSigTest() {
        SecureRandom random = new SecureRandom();
        Map<Integer, Integer> lengthHistogram = new TreeMap<>();
        Map<Character, Integer> firstCharHistogram = new TreeMap<>();
        long start = System.currentTimeMillis();

        for (int i = 0; i < SAMPLE_COUNT; i++) {
            // 模拟 canonicalEncode 输出的随机性来源；长度这个属性
            // 只取决于 hash20+checksum 的数值分布，跟 canonicalEncode
            // 具体编码了什么内容无关，所以用随机字节驱动即可
            byte[] fakeCanonical = new byte[64];
            random.nextBytes(fakeCanonical);

            byte[] contentHash32 = sha3_256(fakeCanonical);
            // 用 SHA3-256 截断代替业务里的 RIPEMD160，仅为测试方便
            // （不影响长度这个属性 —— 位数只取决于数值大小）
            byte[] hash20 = new byte[20];
            System.arraycopy(contentHash32, 0, hash20, 0, 20);

            byte[] payload = new byte[21];
            payload[0] = MULTI_VERSION_BYTE;
            System.arraycopy(hash20, 0, payload, 1, 20);

            byte[] checksum = first4(sha3_256(sha3_256(payload)));

            byte[] binaryAddress = new byte[25];
            System.arraycopy(payload, 0, binaryAddress, 0, 21);
            System.arraycopy(checksum, 0, binaryAddress, 21, 4);

            // 天然首字符方案：不再手动拼 "M" 前缀
            String address = Base58.encode(binaryAddress);

            lengthHistogram.merge(address.length(), 1, Integer::sum);
            firstCharHistogram.merge(address.charAt(0), 1, Integer::sum);
        }

        long elapsed = System.currentTimeMillis() - start;
        System.out.println("样本数: " + SAMPLE_COUNT + "   耗时: " + elapsed + "ms");
        printHistogram("长度", lengthHistogram);
        printCharHistogram("首字符", firstCharHistogram);

        boolean lengthOk = lengthHistogram.size() == 1 && lengthHistogram.containsKey(34);
        boolean firstCharOk = firstCharHistogram.size() == 1 && firstCharHistogram.containsKey('M');

        System.out.println(lengthOk ? "✅ 长度恒为 34 字符" : "❌ 出现非 34 字符地址");
        System.out.println(firstCharOk ? "✅ 首字符恒为 'M'" : "❌ 出现非 'M' 开头地址");
    }

    private static void printHistogram(String label, Map<Integer, Integer> histogram) {
        for (Map.Entry<Integer, Integer> entry : histogram.entrySet()) {
            double pct = entry.getValue() * 100.0 / SAMPLE_COUNT;
            System.out.printf("  %s %d 字符: %d 次 (%.4f%%)%n", label, entry.getKey(), entry.getValue(), pct);
        }
    }

    private static void printCharHistogram(String label, Map<Character, Integer> histogram) {
        for (Map.Entry<Character, Integer> entry : histogram.entrySet()) {
            double pct = entry.getValue() * 100.0 / SAMPLE_COUNT;
            System.out.printf("  %s \"%s\": %d 次 (%.4f%%)%n", label, entry.getKey(), entry.getValue(), pct);
        }
    }

    private static byte[] sha3_256(byte[] data) {
        SHA3Digest d = new SHA3Digest(256);
        d.update(data, 0, data.length);
        byte[] out = new byte[32];
        d.doFinal(out, 0);
        return out;
    }

    private static byte[] first4(byte[] data) {
        byte[] out = new byte[4];
        System.arraycopy(data, 0, out, 0, 4);
        return out;
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
