package org.que.core.queData;

import com.alibaba.fastjson2.annotation.JSONCreator;
import com.alibaba.fastjson2.annotation.JSONField;
import com.alibaba.fastjson2.annotation.JSONType;
import org.que.util.QubeIdUtil;
// 加上这个注解！！！
@JSONType(
        typeKey = "type",
        seeAlso = {EntityData.class, RuleData.class, TransactionData.class}
)


public abstract class QueBaseData {

    @JSONField(ordinal = 0)
    public String type;

    @JSONField(ordinal = 1)
    public String id;

    @JSONField(ordinal = 2)
    public String contractAddress;

    @JSONField(ordinal = 3)
    public String from;

    @JSONField(ordinal = 4)
    public long timestamp;

    // 主网字段（测试/主网都一样）
    @JSONField(ordinal = 5)
    public String payloadHash;

    @JSONField(ordinal = 6)
    public String signatureHash;




    protected void initBaseFields(String contractAddress) {
        this.type=getType();
        this.id = QubeIdUtil.nextId();
        this.contractAddress = contractAddress;
        this.timestamp = System.currentTimeMillis();
    }

    public abstract String getType();

    // 用于主网签名的原始内容（子类提供）
    public abstract String getPayloadForHash();

    public void finalizeForContainerWrite() {
        if (payloadHash == null || signatureHash == null) {
            throw new RuntimeException("payloadHash / signatureHash 未生成，拒绝写入容器");
        }
        // debug 字段不写入容器，但 JSON 层保留
    }
}
