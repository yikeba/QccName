package org.que.core.queData;


import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONFactory;
import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;

import java.nio.charset.StandardCharsets;
import java.util.List;

public class QubeDataBaseFactory {

    /**
     * 将数据对象序列化为确定性 JSON（OrderedField）
     */
    public static String toJson(QueBaseData data) {
        JSONWriter writer = JSONWriter.of(
                JSONWriter.Feature.WriteMapNullValue,   // 写 null
                JSONWriter.Feature.NotWriteDefaultValue // 不写默认值
                // ❌ 不要 FieldOrder（不存在）
                // ❌ 不要 OrderedField（旧版本）
        );
        writer.writeAny(data);
        return writer.toString();
    }

    public static String toJson(List<QueBaseData> list) {

        JSONWriter writer = JSONWriter.of(
                JSONWriter.Feature.WriteMapNullValue,
                JSONWriter.Feature.NotWriteDefaultValue
        );

        writer.startArray();
        for (QueBaseData data : list) {
            writer.writeAny(data); // 这里 fastjson2 会自动序列化子类
        }
        writer.endArray();

        return writer.toString();
    }



    /**
     * JSON → 对象
     */
    public static QueBaseData fromJson(String json) {
        JSONObject obj = JSON.parseObject(json);
        String type = obj.getString("type");

        if ("transaction".equals(type)) {
            return JSON.parseObject(json, TransactionData.class);
        }
        if ("entity".equals(type)) {
            return JSON.parseObject(json, EntityData.class);
        }
        if ("rule".equals(type)) {
            return JSON.parseObject(json, RuleData.class);
        }

        throw new RuntimeException("Unknown data type: " + type);
    }

    /**
     * 对象 → byte[]（未来主网可替换为二进制格式）
     */
    public static byte[] toBytes(QueBaseData data) {
        return toJson(data).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * byte[] → 对象（JSON 模式）
     */
    public static QueBaseData fromBytes(byte[] bytes) {
        return fromJson(new String(bytes, StandardCharsets.UTF_8));
    }
}

