package org.que.core.queBlock;


import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONWriter;
import org.que.core.queData.QueBaseData;

import java.io.Serializable;

/**
 * JSON 测试网版区块（Base Block）
 * 由 Head + Body + Foot 组成
 */
public class QueBaseBlock implements Serializable {

    public QueBlockHead head;
    public QueBlockBody body;
    public QueBlockFoot foot;

    public QueBaseBlock() {
        this.head = new QueBlockHead();
        this.body = new QueBlockBody();
        this.foot = new QueBlockFoot();
    }

    /**
     * 初始化区块（创建时指定高度、版本、前哈希）
     */
    public QueBaseBlock(long blockNumber, String version, String prevHash) {
        this.head = new QueBlockHead(blockNumber, version, prevHash);
        this.body = new QueBlockBody();
        this.foot = new QueBlockFoot();
    }

    /**
     * 添加数据
     */
    public void addData(QueBaseData data) {
        body.addData(data);
    }

    /**
     * 构建整个区块：
     * 1. 计算 dataListHash
     * 2. 计算 blockHash
     */
    public void build() {

        // 1. 构建数据哈希
        body.buildDataListHash();

        // 2. 构建区块哈希
        foot.buildBlockHash(head, body);
    }

    /**
     * 校验整个区块完整性
     */
    public boolean verify() {
        // 1. dataListHash 是否匹配
        body.buildDataListHash();
        // 2. blockHash 是否匹配
        return foot.verify(head, body);
    }

    /**
     * 区块 → JSON
     */
    public String toJson() {
        JSONWriter writer = JSONWriter.of(
                JSONWriter.Feature.WriteMapNullValue,
                JSONWriter.Feature.NotWriteDefaultValue,
                JSONWriter.Feature.FieldBased           // ← 新加！红线消失
        );
        writer.writeAny(this);
        return writer.toString();
    }

    /**
     * JSON → 区块
     */
    public static QueBaseBlock fromJson(String json) {
        return JSON.parseObject(json, QueBaseBlock.class);
    }

    @Override
    public String toString() {
        return "QueBaseBlock{" +
                "head=" + head +
                ", body=" + body +
                ", foot=" + foot +
                '}';
    }
}
