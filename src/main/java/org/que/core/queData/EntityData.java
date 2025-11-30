package org.que.core.queData;


import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.annotation.JSONField;

public class EntityData extends QueBaseData {

    private static final String TYPE = "entity";

    @JSONField(ordinal = 7)
    public String owner;

    @JSONField(ordinal = 8)
    public String content;

    public EntityData(String contractAddress) {
        initBaseFields(contractAddress);
    }

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public String getPayloadForHash() {
        return id + "|" + contractAddress + "|" + owner + "|" + content;
    }

    public String toJsonString() {
        return JSON.toJSONString(this);
    }
}
