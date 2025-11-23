package org.example.core.ChainData;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.util.encoders.Hex;

public class DataRecord extends AbstractQubeData {

    private final String recordType;
    private final byte[] dataPayload;

    public DataRecord(
            String recordType,
            byte[] dataPayload,
            long feeAmount,
            byte[] senderPubKey,
            byte[] signature) {

        super(ChainDataType.DATA_RECORD.typeId, feeAmount, senderPubKey, signature);

        // 构造器字段赋值
        if (recordType == null || dataPayload == null) {
            throw new IllegalArgumentException("RecordType and Payload must not be null.");
        }
        this.recordType = recordType;
        this.dataPayload = dataPayload;
    }

    /**
     * 【标准 1：构造/验证】静态工厂方法，用于从 byte[] 反序列化。
     */
    public static DataRecord parseFrom(byte[] fullDataBytes) throws IOException {
        // [TODO: 实现细节] 需要使用 DataInputStream/ByteBuffer 逐字节读取和验证
        // 确保读取顺序与 toByteArray() 中的写入顺序严格一致
        throw new UnsupportedOperationException("DataRecord Deserialization TBD.");
    }

    /**
     * 【核心实现】定义 Payload Body 的写入顺序和结构。
     */
    @Override
    protected byte[] getPayloadBody() throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(baos)) {
            // 1. 写入 RecordType (写入长度 + 写入内容)
            byte[] typeBytes = recordType.getBytes(StandardCharsets.UTF_8);
            dos.writeInt(typeBytes.length);
            dos.write(typeBytes);
            // 2. 写入 Data Payload Length
            dos.writeInt(dataPayload.length);
            // 3. 写入 Data Payload
            dos.write(dataPayload);
            dos.flush();
            return baos.toByteArray();
        }
    }

    /**
     * 【标准 3：可视化】返回供外部审计使用的可读字符串。
     */
    @Override
    public String toAuditString() {
        return String.format("DataRecord [Type=%s, Sender=%s, Length=%d]",
                this.recordType,
                Hex.toHexString(this.senderPubKey),
                this.dataPayload.length);
    }

    /**
     * 【标准 3：可视化】返回供 Applet 使用的 JSON 格式数据。
     */
    @Override
    public String toJSON() {
        return String.format(
                """
                {
                  "typeId": "%s",
                  "timestamp": %d,
                  "senderPubKey": "%s",
                  "recordType": "%s",
                  "dataPayloadHex": "%s"
                }
                """,
                Hex.toHexString(new byte[]{this.typeId}),
                this.timestamp,
                Hex.toHexString(this.senderPubKey),
                this.recordType,
                Hex.toHexString(this.dataPayload)
        );
    }
}