package org.example.core.ChainData;


import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;

/**
 * QubeDataFactory: 负责根据传入数据的 TypeID，将原始 byte[] 动态解析为具体的 QubeData 对象。
 * 这是 X-Server 接收数据流后的第一步。
 */
public class QubeDataFactory {

    /**
     * 根据 TypeID 动态解析 byte[] 数据流。
     * * @param fullDataBytes 完整的 QubeData 字节数组，包括 Header 和 Payload。
     * @return 动态生成的 SerializableData 对象 (DataRecord, Transaction, SystemCall)。
     * @throws IOException 如果数据读取失败或 TypeID 无效。
     */
    public static ChainData parse(byte[] fullDataBytes) throws IOException {
        if (fullDataBytes == null || fullDataBytes.length < 1) {
            throw new IOException("Data is empty or too short to read TypeID.");
        }

        // 1. 读取第一个字节：TypeID
        byte typeId = fullDataBytes[0];

        // 2. 路由解析
        switch (typeId) {
            case ChainData.TYPE_ID_DATA_RECORD:
                // 路由到 DataRecord 类的静态解析方法
                return DataRecord.parseFrom(fullDataBytes);

            case ChainData.TYPE_ID_TRANSACTION:
                // [TODO: 下一步实现] 路由到 Transaction 类的静态解析方法
                // return Transaction.parseFrom(fullDataBytes);
                throw new UnsupportedOperationException("Type 0x01 Transaction parsing not yet implemented.");

            case ChainData.TYPE_ID_SYSTEM_CALL:
                // [TODO: 下一步实现] 路由到 SystemCall 类的静态解析方法
                // return SystemCall.parseFrom(fullDataBytes);
                throw new UnsupportedOperationException("Type 0x03 SystemCall parsing not yet implemented.");

            default:
                throw new IOException("Unknown or Invalid TypeID: 0x" + String.format("%02X", typeId));
        }
    }

    // [注意]: 对于超级主服务器通知的 SystemCall 数据，可以走单独的内部通道，
    // 或在 TypeID 0x03 的解析逻辑中加入签名验证逻辑，确认是系统内部数据。
}