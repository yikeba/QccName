package org.example.core.ChainData;
import java.io.IOException;

/**
 * SerializableData: QubeChain 中所有数据单元（交易、区块、容器）的抽象基础接口。
 * 确保所有核心对象都具备高效的字节序列化和反序列化能力。
 */
public interface ChainData {
    // ====================== 核心序列化方法 ======================

    /**
     * 将当前数据对象转换为紧凑的字节数组。
     */
    byte[] toByteArray() throws IOException;
    /**
     * 计算当前对象的确定性哈希值 (例如，SHA3-256)。
     */
    byte[] calculateHash();
    // ====================== 数据类型标识符 ======================
    /**
     * 获取数据负载的类型标识符。
     * 用于在网络传输中，指示接收方（如 X 服务器）应如何解析和处理此数据。
     *
     * @return 数据的类型 ID (例如，1 = Transaction, 2 = DataRecord, 3 = SystemCall)。
     */
    byte getDataTypeId();

    // ====================== 静态常量定义 ======================

    // 推荐使用 byte 类型（占用 1 字节）来存储类型 ID
    byte TYPE_ID_TRANSACTION = 0x01;  // 交易（资产转移/状态修改）
    byte TYPE_ID_DATA_RECORD = 0x02;  // 数据记录（纯粹的存储证明/文件哈希）
    byte TYPE_ID_SYSTEM_CALL = 0x03;  // 系统调用（链内参数/节点状态变更）
}