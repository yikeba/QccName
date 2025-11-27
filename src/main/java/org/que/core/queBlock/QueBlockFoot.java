package org.que.core.queBlock;


import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONWriter;
import org.que.crypto.CryptoUtil;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;

/**
 * 区块尾（Block Foot）
 * 负责最终 blockHash，也预留未来扩展空间（签名、节点凭证、指纹等）
 */
public class QueBlockFoot implements Serializable {

    /** 区块最终哈希（SHA3-256） */
    public String blockHash;

    /** 扩展字段（未来可用于存节点签名、多签、指纹、共识证明等） */
    public String extra;  // 可为 JSON、字符串、备注，随你扩展

    public QueBlockFoot() { }

    /**
     * 构建区块最终哈希：
     *
     * blockHash = SHA3-256( headJson + "|" + dataListHash )
     *
     * 这是区块链的核心绑定逻辑。
     */
    public void buildBlockHash(QueBlockHead head, QueBlockBody body) {

        // 1. 区块头 JSON（确定性序列化）
        String headJson = toCanonicalJson(head);

        // 2. 拼接 payload
        String payload = headJson + "|" + body.dataListHash;

        // 3. SHA3-256
        this.blockHash = CryptoUtil.sha3256Hex(
                payload.getBytes(StandardCharsets.UTF_8)
        );
    }

    /**
     * 验证区块哈希是否正确
     */
    public boolean verify(QueBlockHead head, QueBlockBody body) {

        String headJson = toCanonicalJson(head);
        String payload = headJson + "|" + body.dataListHash;

        String expectedHash = CryptoUtil.sha3256Hex(
                payload.getBytes(StandardCharsets.UTF_8)
        );

        return expectedHash.equals(this.blockHash);
    }

    /**
     * 供区块内部使用的确定性 JSON 转换（只用于 Head、Body，不用数据工厂）
     */
    private static String toCanonicalJson(Object obj) {
        JSONWriter writer = JSONWriter.of(
                JSONWriter.Feature.WriteMapNullValue,
                JSONWriter.Feature.NotWriteDefaultValue,
                JSONWriter.Feature.FieldBased           // ← 新加！红线消失
        );
        writer.writeAny(obj);
        return writer.toString();
    }

    @Override
    public String toString() {
        return "QueBlockFoot{" +
                "blockHash='" + blockHash + '\'' +
                ", extra='" + extra + '\'' +
                '}';
    }
}
