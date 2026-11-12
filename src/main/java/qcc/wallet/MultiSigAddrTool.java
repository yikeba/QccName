package qcc.qccwallet;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.util.encoders.Hex;
import qcc.constitution.ChainIdentity;
import qcc.util.Base58;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/**
 * ════════════════════════════════════════════════════════
 * 多签地址 —— 天然 34 字符定长方案 (与单签 0x3A 同批协议变更)
 * 上一版 MULTI_VERSION_BYTE=0x05，需手动拼接 "M" + base58(...)，
 * 结果恒为 35 字符（已用 10 万样本验证过定长性，只是需要手动
 * 拼前缀）。这一版改用 v=0x33，让 Base58 编码结果本身天然以
 * 'M' 开头，不再手动拼前缀，整体恒为 34 字符。
 * 精确验证（大整数运算）：25字节数值区间
 * [0x33×256^24, 0x34×256^24) 内，任意 hash20+checksum 取值，
 * Base58 编码结果长度恒为 34、首字符恒为 'M'。
 * ⚠️ 协议级变更：所有用旧 0x05 版本生成的多签地址均已作废，
 * 需按迁移处理。
 * ════════════════════════════════════════════════════════
 */
public class MultiSigAddrTool {

    // 多签地址版本号（payload[0]）—— 天然34字符M开头方案
    private static final byte MULTI_VERSION_BYTE = 0x33;

    // 多签规则编码版本（用于未来升级编码规则）
    private static final byte MS_RULE_VERSION = 0x01;

    public static String deriveMultiAddrFromPubKeys(List<String> ownerPubKeyHex,
                                                    int thresholdM
                                                    ) {
        if (ownerPubKeyHex == null || ownerPubKeyHex.isEmpty()) return null;
        if (thresholdM <= 0) return null;

        // 1) pubkeys -> bytes，并做清洗
        List<byte[]> pubKeys = new ArrayList<>();
        for (String hex : ownerPubKeyHex) {
            if (hex == null) return null;
            String clean = hex.replaceAll("[^0-9a-fA-F]", "");
            byte[] pk = Hex.decode(clean);
            pubKeys.add(pk);
        }

        int n = pubKeys.size();
        if (thresholdM > n) return null;

        // 2) 按字节序排序，保证 owners 顺序不影响地址
        pubKeys.sort(lexicographicalBytesComparator());

        // 3) canonical encode（纯二进制，不用 JSON）
        byte[] canonical = canonicalEncode(pubKeys, thresholdM);

        // 4) contentHash32 = SHA3-256(canonical)
        byte[] contentHash32 = sha3_256(canonical);

        // 5) hash20 = RIPEMD160(contentHash32)
        byte[] hash20 = ripemd160(contentHash32);

        // 6) payload = version + hash20
        byte[] payload = new byte[21];
        payload[0] = MULTI_VERSION_BYTE;
        System.arraycopy(hash20, 0, payload, 1, 20);

        // 7) checksum = first4(sha3(sha3(payload)))
        byte[] checksum = first4(sha3_256(sha3_256(payload)));

        // 8) binaryAddress = payload + checksum
        byte[] binaryAddress = new byte[25];
        System.arraycopy(payload, 0, binaryAddress, 0, 21);
        System.arraycopy(checksum, 0, binaryAddress, 21, 4);

        // 9) 直接返回 Base58 编码结果 —— 不再手动拼 "M" 前缀，
        //    'M' 本身就是编码结果的天然首字符
        return Base58.encode(binaryAddress);
    }

    /**
     * 校验多签地址格式 + checksum
     * 地址长度恒定 34 字符，天然以 'M' 开头
     */
    public static boolean isValidMultiSigAddress(String address) {
        if (address == null || address.length() != 34) {
            return false;
        }
        try {
            byte[] binaryAddress = Base58.decode(address);
            if (binaryAddress.length != 25) {
                return false;
            }
            if (binaryAddress[0] != MULTI_VERSION_BYTE) {
                return false;
            }

            byte[] payload = Arrays.copyOfRange(binaryAddress, 0, 21);
            byte[] checksum = Arrays.copyOfRange(binaryAddress, 21, 25);
            byte[] expectedChecksum = first4(sha3_256(sha3_256(payload)));

            return Arrays.equals(checksum, expectedChecksum);
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] canonicalEncode(List<byte[]> pubKeys, int m) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            // MAGIC + version
            out.write("QCCMS".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            out.write(MS_RULE_VERSION);

            // chainId (string) => [len(2 bytes BE) + utf8 bytes]
            String cid = "6666";
            byte[] cidBytes = cid.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            out.write(shortToBytesBE((short) cidBytes.length));
            out.write(cidBytes);

            // m, n (2 bytes each, BE)
            out.write(shortToBytesBE((short) m));
            out.write(shortToBytesBE((short) pubKeys.size()));

            // pubkeys: [pkLen(2 bytes) + pkBytes]...
            for (byte[] pk : pubKeys) {
                out.write(shortToBytesBE((short) pk.length));
                out.write(pk);
            }
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    private static byte[] sha3_256(byte[] data) {
        SHA3Digest d = new SHA3Digest(256);
        d.update(data, 0, data.length);
        byte[] out = new byte[32];
        d.doFinal(out, 0);
        return out;
    }

    private static byte[] ripemd160(byte[] data) {
        RIPEMD160Digest r = new RIPEMD160Digest();
        r.update(data, 0, data.length);
        byte[] out = new byte[20];
        r.doFinal(out, 0);
        return out;
    }

    private static byte[] first4(byte[] data) {
        return Arrays.copyOfRange(data, 0, 4);
    }

    private static byte[] shortToBytesBE(short v) {
        return ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).putShort(v).array();
    }

    private static Comparator<byte[]> lexicographicalBytesComparator() {
        return (a, b) -> {
            int len = Math.min(a.length, b.length);
            for (int i = 0; i < len; i++) {
                int ai = a[i] & 0xFF;
                int bi = b[i] & 0xFF;
                if (ai != bi) return Integer.compare(ai, bi);
            }
            return Integer.compare(a.length, b.length);
        };
    }
}
