package org.example.core.ChainData;

import java.io.IOException;

// ChainDataType.java
public enum ChainDataType {
    TRADE   (0x01, TradeRecord::parseFrom),    // 交易：转账、发币、股票、NFT
    RULE    (0x02, RuleRecord::parseFrom),     // 规则：发票、合同、公告、DAO提案
    ENTITY  (0x03, EntityRecord::parseFrom);   // 实体：人、企业、国家、证书、身份

    public final byte typeId;
    private final DataParser parser;
    ChainDataType(int id, DataParser p) { this.typeId = (byte)id; this.parser = p; }
    public static ChainDataType fromId(byte id) {
        return switch (id) {
            case 0x01 -> TRADE;
            case 0x02 -> RULE;
            case 0x03 -> ENTITY;
            default -> throw new IllegalArgumentException("未知类型: 0x" + Integer.toHexString(id & 0xFF));
        };
    }
}
@FunctionalInterface interface DataParser { AbstractQubeData parse(byte[] d) throws IOException; }