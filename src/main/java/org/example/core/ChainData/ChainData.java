// ChainData.java —— 终极进化版（枚举驱动 · 常量全灭 · 永封版）
package org.example.core.ChainData;

import java.io.IOException;

/**
 * ChainData: 所有上链数据对象的统一接口
 * 2025年全球最硬版本：完全由 ChainDataType 枚举驱动！
 */
// ChainData.java —— 终极进化版（类型是属性！不是方法！）

import java.io.IOException;

public interface ChainData {

    // 序列化
    byte[] toByteArray() throws IOException;

    // 计算哈希
    byte[] calculateHash();

    // 类型是属性！不是方法！最硬！最纯粹！
    ChainDataType TYPE = null; // 每个实现类必须赋值！

    // 兼容旧代码（最终删除）
    @Deprecated(since = "2025-11-23", forRemoval = true)
    default ChainDataType getDataType() {
        return TYPE;
    }

    default byte getDataTypeId() {
        return TYPE.typeId;
    }
}