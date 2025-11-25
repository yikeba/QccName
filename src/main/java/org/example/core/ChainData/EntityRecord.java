package org.example.core.ChainData;// EntityRecord.java —— 使用 FastJson2 终极版
import com.alibaba.fastjson2.JSONObject;   // 重点！这就是最快的
import com.alibaba.fastjson2.JSONWriter;
import org.example.core.ChainData.AbstractQubeData;
import org.example.core.ChainData.ChainDataType;
import org.example.crypto.CryptoUtil;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class EntityRecord extends AbstractQubeData {

    private String entityType;     // person, company, country...
    private String entityId;       // 身份证、统一社会信用代码
    private String name;           // 名称

    // 万能属性袋 —— 改用 FastJson2 的 JSONObject（宇宙最快！）
    private final JSONObject attributes;

    public EntityRecord(String entityType, String entityId, String name,
                        JSONObject attributes,
                        long feeAmount, byte[] pubKey, byte[] signature,byte[] contractAddress) {
        super(ChainDataType.ENTITY, feeAmount, pubKey, signature,contractAddress);
        this.entityType = entityType;
        this.entityId = entityId;
        this.name = name;
        this.attributes = attributes != null ? attributes : new JSONObject();
    }

    // ==================== 序列化：FastJson2 自带超快序列化 ====================
    @Override
    protected byte[] serializePayload() throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(baos)) {

            writeString(dos, entityType);
            writeString(dos, entityId);
            writeString(dos, name);

            // 直接用 FastJson2 的二进制协议！比 UTF-8 还快！
            byte[] jsonBytes = attributes.toJSONString().getBytes(StandardCharsets.UTF_8);
            // 或者更牛：用 FastJson2 的二进制格式（兼容性差点，但更快）
            // byte[] jsonBytes = attributes.toJSONBBytes();

            dos.writeInt(jsonBytes.length);
            dos.write(jsonBytes);

            return baos.toByteArray();
        }
    }

    @Override
    protected void deserializePayload(DataInputStream dis) throws IOException {
        this.entityType = readString(dis);
        this.entityId = readString(dis);
        this.name = readString(dis);

        int jsonLen = dis.readInt();
        if (jsonLen < 0) throw new IOException("JSON长度异常");

        byte[] jsonBytes = new byte[jsonLen];
        dis.readFully(jsonBytes);

        // 正确方式！必须先转 String 再解析（FastJson2 推荐写法）
        String jsonStr = new String(jsonBytes, StandardCharsets.UTF_8);
        this.attributes.putAll(JSONObject.parseObject(jsonStr));

        // 或者一行更优雅（推荐！）
        // this.attributes = JSONObject.parseObject(jsonBytes, StandardCharsets.UTF_8);
        // 注意：这个方法在 FastJson2 中也支持，但需要确保字符集正确
    }
    // ==================== 全局唯一 parseFrom ====================
    public static EntityRecord parseFrom(byte[] data) throws IOException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
        dis.readByte(); // typeId
        long ts = dis.readLong();
        long fee = dis.readLong();
        byte[] pubKey = readVarBytes(dis);
        byte[] sig = readVarBytes(dis);
        dis.readNBytes(32); // hash

        byte[] contractAddress = readVarBytes(dis);
        if (contractAddress.length == 0) {
            throw new IOException("反序列化时发现 contractAddress 为空！");
        }

        int payloadLen = dis.readInt();

        EntityRecord r = new EntityRecord("", "", "", new JSONObject(), fee, pubKey, sig,contractAddress);
        r.setTimestamp(ts);

        byte[] payload = new byte[payloadLen];
        dis.readFully(payload);
        r.deserializePayload(new DataInputStream(new ByteArrayInputStream(payload)));

        return r;
    }

    @Override
    public boolean verifyIntegrity() {
        try {
            // 重新序列化当前所有字段（必须和当初一模一样）
            byte[] currentPayload = serializePayload();
            byte[] currentHash = CryptoUtil.sha3256(currentPayload);
            // 和链上保存的原始哈希对比
            return Arrays.equals(getOriginalPayloadHash(), currentHash);
        } catch (Exception e) {
            return false;
        }
    }
    // ==================== toJSON：直接返回最快字符串 ====================
    @Override
    public String toJSON() {
        // FastJson2 自带超快序列化，带美化也比 Gson 快！
        return attributes.toJSONString(JSONWriter.Feature.PrettyFormat);
    }

    @Override
    public String toAuditString() {
        return String.format("实体 [%s] %s | ID:%s | 属性:%d项 | 示例:%s",
                entityType, name, entityId.substring(0, Math.min(16, entityId.length())),
                attributes.size(),
                attributes.size() > 0 ? attributes.entrySet().iterator().next() : "无");
    }

    // Getter
    public JSONObject getAttributes() { return attributes; }
}