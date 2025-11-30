package org.que.core.queData;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.annotation.JSONField;

public class RuleData extends QueBaseData {

    private static final String TYPE = "rule";

    @JSONField(ordinal = 7)
    public String ruleType;

    @JSONField(ordinal = 8)
    public String ruleJson;

    public RuleData(String contractAddress) {
        initBaseFields(contractAddress);
    }

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public String getPayloadForHash() {
        return id + "|" + contractAddress + "|" + ruleType + "|" + ruleJson;
    }

    public String toJsonString() {
        return JSON.toJSONString(this);
    }
}
