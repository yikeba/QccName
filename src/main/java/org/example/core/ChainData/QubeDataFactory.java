// QubeDataFactory.java —— 终极纯byte[]版（零JSON！零反射！零GC！全球最硬！）
package org.example.core.ChainData;


import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.example.crypto.QubeSigner;
import org.example.storage.AddressIndexService;
import org.example.util.GzipUtil;

import java.io.IOException;

public final class QubeDataFactory {

    private QubeDataFactory() {
        throw new AssertionError("禁止实例化");
    }

    // 主力入口：100%纯byte[]解析（主网唯一路径！）
    public static ChainData parse(byte[] fullDataBytes) throws IOException {
        if (fullDataBytes == null || fullDataBytes.length < 1) {
            throw new IOException("数据为空或太短");
        }

        byte typeId = fullDataBytes[0];
        ChainDataType type = ChainDataType.fromTypeId(typeId);

        return switch (type) {
            case TRANSACTION          -> Transaction.parseFrom(fullDataBytes);
            case DATA_RECORD          -> DataRecord.parseFrom(fullDataBytes);
            case SYSTEM_CALL          -> SystemCall.parseFrom(fullDataBytes);
            case BALANCE_CONFIRMATION -> BalanceConfirmation.parseFrom(fullDataBytes);
           // case FILE_PROOF           -> FileProof.parseFrom(fullDataBytes);
           // case STATE_SNAPSHOT       -> StateSnapshot.parseFrom(fullDataBytes);
        };
    }

    // 兼容层：Base64 → byte[]（仅用于旧客户端或调试）
    public static ChainData parseFromBase64(String base64) throws IOException {
        return parse(Base64.decode(base64));
    }

    // 最硬主网协议：压缩包 + 签名 + 地址（但内部100%走byte[]！）
    public static ChainData parseFromCompressedPackage(
            String compressedBase64,
            String signatureBase64,
            String address) throws IOException {

        byte[] compressed = Base64.decode(compressedBase64);
        byte[] signature = Base64.decode(signatureBase64);

        // 1. 解压得到标准字节流
        byte[] standardBytes = GzipUtil.decompress(compressed);

        // 2. 验签（对解压后的标准字节流验签！最硬！）
        String pubKeyHex = AddressIndexService.getInstance().getPubKeyHex(address);
        if (!QubeSigner.verifyRaw(standardBytes, signature, Hex.decode(pubKeyHex))) {
            throw new SecurityException("签名验证失败！数据被篡改！");
        }

        // 3. 100%走标准byte[]解析！零JSON！零反射！
        return parse(standardBytes);
    }

    // 完全删除 parseFromJson！永不后悔！
    // public static ChainData parseFromJson(...) { throw new UnsupportedOperationException("主网禁用JSON解析"); }
}