// ChainDataType.java —— 终极兼容版（零破坏迁移！全球最硬！）
package org.example.core.ChainData;

public enum ChainDataType {
    TRANSACTION         (0x01, "transfer"),
    DATA_RECORD         (0x02, "data_record"),
    SYSTEM_CALL         (0x03, "system_call"),
    BALANCE_CONFIRMATION(0x04, "balance_confirmation");

    public final byte typeId;
    public final String typeName;

    ChainDataType(int typeId, String typeName) {
        this.typeId = (byte) typeId;
        this.typeName = typeName;
    }

    public static ChainDataType fromTypeId(byte typeId) {
        for (ChainDataType t : values()) {
            if (t.typeId == typeId) return t;
        }
        throw new IllegalArgumentException("未知TypeID: 0x" + String.format("%02X", typeId));
    }

    public static ChainDataType fromTypeName(String name) {
        for (ChainDataType t : values()) {
            if (t.typeName.equals(name)) return t;
        }
        throw new IllegalArgumentException("未知类型名: " + name);
    }
}