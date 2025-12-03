package org.que.core.queBlock;

import org.que.core.queData.QubeDataBaseFactory;
import org.que.core.queData.QueBaseData;
import org.que.crypto.CryptoUtil;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * 区块 Body：只负责存储数据和计算 dataListHash
 */
public class QueBlockBody implements Serializable {

    public List<QueBaseData> dataList = new ArrayList<>();
    public String dataListHash;     // SHA256(dataList JSON)

    public QueBlockBody() { }

    /**
     * 添加数据
     */
    public void addData(QueBaseData data) {

        dataList.add(data);
    }

    /**
     * 计算 dataListHash
     * 必须在数据添加完成后调用
     */
    public void buildDataListHash() {
        // 1. 序列化整个 dataList 为 JSON 字符串
        String json = QubeDataBaseFactory.toJson(dataList);
        // 2. SHA-256(JSON)
        this.dataListHash =CryptoUtil.sha3256Hex(json);
    }

    @Override
    public String toString() {
        return "QueBlockBody{" +
                "dataList size=" + dataList.size() +
                ", dataListHash='" + dataListHash + '\'' +
                '}';
    }
}
