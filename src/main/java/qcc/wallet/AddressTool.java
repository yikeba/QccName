package qcc.qccwallet;

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.digests.SHA3Digest;
import qcc.config.QccPath;
import qcc.util.Base58;

import java.util.Arrays;

/**
 * QCC 单签地址生成工具 (服务端版) —— 天然 34 字符定长方案
 * 职责：验证 QccWallet 传来的公钥，计算出的地址是否与 claimed address 一致。
 * 算法： Base58( Version(0x3A) + SHA3-256(PubKey)[0:20] + Checksum )
 * ════════════════════════════════════════════════════════
 * 第二次协议变更说明（与 Dart AddressTool_34char.dart 同步）：
 *   上一版 version=0x10，需要手动拼接 "Q" + base58(...)，
 *   结果恒为 35 字符。这一版改用 v=0x3A，让 Base58 编码结果
 *   本身天然以 'Q' 开头，不再手动拼前缀，整体恒为 34 字符。
 *   精确验证（大整数运算，非对数估算）：25字节数值区间
 *   [0x3A×256^24, 0x3B×256^24) 内，任意 hash20+checksum 取值，
 *   Base58 编码结果长度恒为 34、首字符恒为 'Q'。
 *   碰撞抗性不受影响：version byte 贡献 0 bit 熵，真正的碰撞
 *   抗性完全由 hash20 (160 bit, SHA3-256 截断) 决定，与之前
 *   35 字符方案完全相同；34 字符唯一的优势是少存 1 字符，
 *   千万级地址规模下有真实的内存收益。
 *   ⚠️ 这是第二次协议级变更，version byte 必须与 Flutter 端
 *   严格同步为 0x3A，旧的 0x00 / 0x10 版本地址均已作废。
 * ════════════════════════════════════════════════════════
 */
public class AddressTool {

    // QCC 单签地址版本号 —— 唯一权威来源，其他类不要再各自声明一份
    private static final byte QCC_VERSION_BYTE = 0x3A;

    public static byte getVersionByte() {
        return QCC_VERSION_BYTE;
    }

    /**
     * 根据公钥 Hex 推导地址
     * @param publicKeyHex Dilithium5 公钥 Hex 字符串 (5184 chars)
     * @return 固定 34 字符，天然以 'Q' 开头 (如: Q1B9fiSiPZ...)
     */
    public static String creatAddress(String publicKeyHex) {
        if (publicKeyHex == null || publicKeyHex.isEmpty()) {
            return null;
        }
        try {
            // 0. Hex 解码 (得到 2592 字节的原始公钥)
            String cleanHex = publicKeyHex.replaceAll("[^0-9a-fA-F]", "");
            byte[] pubKeyBytes = Hex.decode(cleanHex);

            // 1. SHA3-256
            SHA3Digest sha3Digest = new SHA3Digest(256);
            sha3Digest.update(pubKeyBytes, 0, pubKeyBytes.length);
            byte[] hash = new byte[32];
            sha3Digest.doFinal(hash, 0);
            byte[] hash20 = Arrays.copyOf(hash, 20); // 取前 20 字节作为地址核心

            // 2. 构建 Versioned Payload (1 byte version + 20 bytes hash)
            byte[] versionedPayload = new byte[21];
            versionedPayload[0] = QCC_VERSION_BYTE; // 0x3A
            System.arraycopy(hash20, 0, versionedPayload, 1, 20);

            // 3. 计算 Checksum (Double SHA3-256)
            sha3Digest = new SHA3Digest(256);
            sha3Digest.update(versionedPayload, 0, versionedPayload.length);
            byte[] firstSHA = new byte[32];
            sha3Digest.doFinal(firstSHA, 0);

            sha3Digest = new SHA3Digest(256);
            sha3Digest.update(firstSHA, 0, firstSHA.length);
            byte[] secondSHA = new byte[32];
            sha3Digest.doFinal(secondSHA, 0);

            byte[] checksum = new byte[4];
            System.arraycopy(secondSHA, 0, checksum, 0, 4);

            // 4. 拼接最终二进制地址 [Version + Hash20 + Checksum] (共 25 bytes)
            byte[] binaryAddress = new byte[25];
            System.arraycopy(versionedPayload, 0, binaryAddress, 0, 21);
            System.arraycopy(checksum, 0, binaryAddress, 21, 4);

            // 5. 直接返回 Base58 编码结果 —— 不再手动拼 "Q" 前缀，
            //    'Q' 本身就是编码结果的天然首字符
            return Base58.encode(binaryAddress);

        } catch (Exception e) {
            System.err.println("[AddressTool] Error deriving address: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 校验地址格式 + checksum，供服务端验证客户端上报地址时使用。
     * 修复后地址长度恒定 34 字符，天然以 'Q' 开头。
     */
    public static boolean isValidAddress(String address) {
        if (address == null || address.length() != 34) {
            return false;
        }
        try {
            byte[] binaryAddress = Base58.decode(address);
            if (binaryAddress.length != 25) {
                return false;
            }
            if (binaryAddress[0] != QCC_VERSION_BYTE) {
                return false;
            }

            byte[] versionedPayload = Arrays.copyOfRange(binaryAddress, 0, 21);
            byte[] checksum = Arrays.copyOfRange(binaryAddress, 21, 25);

            SHA3Digest sha3Digest = new SHA3Digest(256);
            sha3Digest.update(versionedPayload, 0, versionedPayload.length);
            byte[] firstSHA = new byte[32];
            sha3Digest.doFinal(firstSHA, 0);

            sha3Digest = new SHA3Digest(256);
            sha3Digest.update(firstSHA, 0, firstSHA.length);
            byte[] secondSHA = new byte[32];
            sha3Digest.doFinal(secondSHA, 0);

            for (int i = 0; i < 4; i++) {
                if (checksum[i] != secondSHA[i]) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }


    public static void testaddress() throws Exception {
        int count=100000;
        System.out.println("========== ✨ Genesis Wallet Generate ✨ ==========");
        boolean is35=true;
        for (int i = 0; i < count; i++) {
            // 创建钱包对象
            QccWallet wallet = WalletUtil.createWallet();
            if(wallet.address.length()==34){
                System.out.println("地址生成长度："+wallet.address.length()+"生成累计数量:"+i+" 地址内容:"+wallet.address);
            }else{
                System.err.println("地址生成长度："+wallet.address.length()+"生成累计数量:"+i+" 地址内容:"+wallet.address);
                break;
            }
        }

    }


    public static void main(String[] args) throws Exception {
        QccPath.init(); // 就这一行！！！所有路径搞定！！！
        System.out.println("╔══════════════════════════════════════╗");
        System.out.println("║    QCC-Chain ∞ 全球最硬容器链已启动    ║");
        System.out.println("║  10分钟切容器 | 树状无限扩散 | 抗量子   ║");
        System.out.println("║    测试地址生成1万个判断字符串长度       ║");
        System.out.println("╚══════════════════════════════════════╝");
        testaddress();


    }


}
