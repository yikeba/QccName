// QubeDataFactory.java —— 2025 永封版（只解析已验签的干净数据）
package org.que.core.ChainData;

import java.io.IOException;

/**
 * QubeDataFactory v3.0
 * 职责：只做一件事 —— 把【已验签通过】的纯净 byte[] 解析成 Trade/Rule/Entity 对象
 * 禁止任何验签、防重放、解压、地址解析！
 * 这是业务层的“最后一道纯净之门”
 */
public final class QubeDataFactory {

    private QubeDataFactory() {
        throw new AssertionError("禁止实例化！这是协议解析核心！");
    }

    /**
     * 主力入口：解析已验签通过的原始数据（来自 QubePacket.payload）
     * @param cleanData 已通过签名验证的完整数据字节（AbstractQubeData.toByteArray() 结果）
     */
    public static AbstractQubeData parse(byte[] cleanData) throws IOException {
        if (cleanData == null || cleanData.length < 60) {
            throw new IOException("数据太短或为空，无法解析（长度=" + (cleanData == null ? "null" : cleanData.length) + "）");
        }

        byte typeId = cleanData[0];
        ChainDataType type = ChainDataType.fromId(typeId);

        return switch (type) {
            case TRADE  -> TradeRecord.parseFrom(cleanData);
            case RULE   -> RuleRecord.parseFrom(cleanData);
            case ENTITY -> EntityRecord.parseFrom(cleanData);
            default -> throw new IOException("不支持的数据类型: 0x" + String.format("%02X", typeId));
        };
    }

    /**
     * 调试用：Base64 直接解析（仅用于测试、浏览器、日志回放）
     */
    public static AbstractQubeData parseFromBase64(String base64) throws IOException {
        return parse(org.bouncycastle.util.encoders.Base64.decode(base64));
    }

    /**
     * 运维神器：直接打印人类可读日志
     */
    public static void printAuditLog(byte[] cleanData) throws IOException {
        try {
            AbstractQubeData data = parse(cleanData);
            System.out.println("[链上数据] " + data.toAuditString());
        } catch (Exception e) {
            System.out.println("[非法数据] 解析失败: " + e.getMessage());
        }
    }

    /**
     * 已废弃：所有验签、解压、地址解析必须在通讯层完成！
     * 任何尝试在这里验签的代码都将被视为安全漏洞！
     */
    @Deprecated(forRemoval = true)
    public static AbstractQubeData parseFromCompressedPackage() {
        throw new UnsupportedOperationException("此方法已禁用！验签必须在通讯层完成！");
    }
}