// QubeDataReceiver.java —— 最终正确版：混合解析策略
package org.example.protocol;
import org.bouncycastle.util.encoders.Hex;
import org.example.core.ChainData.*;
import org.example.crypto.QubeAddressUtil;
import org.example.crypto.QubeSigner;
import org.example.storage.AddressIndexService;
import org.example.util.GzipUtil;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.DataInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class QubeDataReceiver {

    private String address;
    private byte[] signature;
    private byte[] fullPackageBytes;
    private byte[] compressedData;
    private byte[] standardBytes;
    private AbstractQubeData parsedData;

    public QubeDataReceiver(byte[] data) {
        try {
            this.fullPackageBytes = data;
            parsePackage();
            verifyAndDecompress();
            parseWithFactory();
        } catch (Exception e) {
            throw new RuntimeException("量子数据接收失败", e);
        }
    }

    public QubeDataReceiver(InputStream inputStream) {
        try {
            this.fullPackageBytes = inputStream.readAllBytes();
            parsePackage();
            verifyAndDecompress();
            parseWithFactory();
        } catch (Exception e) {
            throw new RuntimeException("量子数据接收失败", e);
        }
    }

    /**
     * 正确的解析策略：
     * 1. 从尾部找地址（已知格式：UTF）
     * 2. 地址开始位置 = 签名结束位置
     * 3. 从签名结束位置向前推，找签名长度字段
     * 4. 签名长度字段前就是数据
     */
    private void parsePackage() {
        try {
            int totalLen = fullPackageBytes.length;
            System.out.println("\n【解析数据包】总长度: " + totalLen);

            // ===== 步骤1：从尾部提取地址 =====
            int addrStart = -1;
            int addrTotalLen = -1;

            // 从后往前搜索UTF长度字段
            for (int pos = Math.max(0, totalLen - 50); pos < totalLen - 2; pos++) {
                int testLen = ((fullPackageBytes[pos] & 0xFF) << 8)
                        | (fullPackageBytes[pos + 1] & 0xFF);

                if (testLen > 0 && testLen < 200 && pos + 2 + testLen == totalLen) {
                    addrStart = pos;
                    addrTotalLen = 2 + testLen;
                    break;
                }
            }

            if (addrStart == -1) {
                throw new IllegalStateException("无法找到地址UTF字段！");
            }

            // 读取地址
            byte[] addrPart = Arrays.copyOfRange(fullPackageBytes, addrStart, totalLen);
            try (DataInputStream addrStream = new DataInputStream(new ByteArrayInputStream(addrPart))) {
                this.address = addrStream.readUTF();
            }

            System.out.println("✓ 地址: " + address);
            System.out.println("  地址字段位置: " + addrStart + "-" + (totalLen - 1) + " (长度: " + addrTotalLen + ")");

            // ===== 步骤2：签名结束位置 = 地址开始位置 =====
            int sigEnd = addrStart;

            // ===== 步骤3：向前搜索签名长度字段 =====
            // 签名长度应该在 1000-10000 之间（Dilithium5特征）
            int sigLenPos = -1;
            int sigLen = -1;

            // 从 sigEnd 向前搜索，最多搜索 10000 字节（签名最大可能长度）
            for (int pos = Math.max(0, sigEnd - 10000); pos <= sigEnd - 5; pos++) {
                int testSigLen = ((fullPackageBytes[pos] & 0xFF) << 24)
                        | ((fullPackageBytes[pos + 1] & 0xFF) << 16)
                        | ((fullPackageBytes[pos + 2] & 0xFF) << 8)
                        | (fullPackageBytes[pos + 3] & 0xFF);

                // 验证：pos + 4 + testSigLen 应该等于 sigEnd
                if (testSigLen >= 4000 && testSigLen <= 5000 && pos + 4 + testSigLen == sigEnd) {
                    sigLenPos = pos;
                    sigLen = testSigLen;
                    break;
                }
            }

            if (sigLenPos == -1) {
                throw new IllegalStateException("无法找到签名长度字段！");
            }

            System.out.println("\n【签名字段】");
            System.out.println("  长度字段位置: " + sigLenPos);
            System.out.printf("  内容（HEX）: %02X %02X %02X %02X%n",
                    fullPackageBytes[sigLenPos],
                    fullPackageBytes[sigLenPos + 1],
                    fullPackageBytes[sigLenPos + 2],
                    fullPackageBytes[sigLenPos + 3]);
            System.out.println("  签名长度: " + sigLen);

            // ===== 步骤4：提取签名 =====
            int sigStart = sigLenPos + 4;
            this.signature = Arrays.copyOfRange(fullPackageBytes, sigStart, sigEnd);
            System.out.println("✓ 签名提取完成，实际长度: " + signature.length);

            // ===== 步骤5：提取数据（从开头到签名长度字段） =====
            this.compressedData = Arrays.copyOfRange(fullPackageBytes, 0, sigLenPos);
            System.out.println("✓ 数据长度: " + compressedData.length);

            // ===== 最终校验 =====
            int calculated = compressedData.length + 4 + signature.length + addrTotalLen;
            System.out.println("\n【校验】");
            System.out.println("  " + compressedData.length + " + 4 + "
                    + signature.length + " + " + addrTotalLen + " = " + calculated);
            System.out.println("  实际总长: " + totalLen);

            if (calculated != totalLen) {
                throw new IllegalStateException("长度校验失败！");
            }

            System.out.println("✓ 协议解析成功！\n");

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("协议解析失败", e);
        }
    }

    private void verifyAndDecompress() throws Exception {
        byte[] pubKeyHex = QubeAddressUtil.base58Decode(address);
        if (!QubeSigner.verifyRaw(compressedData, signature, pubKeyHex)) {
            throw new SecurityException("【量子签名失败】数据被篡改！地址: " + address);
        }

        // 测试模式：无压缩
        this.standardBytes = compressedData;
        System.out.println("验签成功 → 标准字节流: " + standardBytes.length + " bytes");
    }

    private void parseWithFactory() throws Exception {
        this.parsedData = (AbstractQubeData) QubeDataFactory.parse(standardBytes);
        System.out.println("业务解析成功 → " + parsedData.toAuditString());
    }

    public AbstractQubeData getData() { return parsedData; }
    public String getAddress() { return address; }
    public byte[] getCompressedData() { return compressedData; }
    public byte[] getStandardBytes() { return standardBytes; }
}