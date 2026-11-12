package qcc.name.chain;

import qcc.name.codec.Sha3;
import qcc.name.protocol.StrictJson;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * 一笔 QCCData 交易（GET /v1/hash/{txHash}，已实测）。
 *
 *   {"ok":true,"kind":"TX","status":"SUCCESS","data":"{\"tx\":\"{…\\\"from\\\":…,\\\"payload\\\":[123,10,…,-26,…]}\",
 *    \"containerId\":…,\"tailHash\":…,\"confirmTimestamp\":…,\"height\":26727,…}"}
 *
 *   data 与 tx 都是转义后的 JSON 字符串，逐层解析；payload 是 Java 有符号字节数组（x & 0xFF 还原）。
 *   排序与生效只用 height（共识确定）；tx.timestamp 是发送方签名时自填的，不可信，不使用。
 */
public record ChainTx(String txHash, String chain, String from, String assetId, long height, long confirmTimestamp,
                      byte[] payload) {

    public String payloadHash() { return Sha3.toHex(Sha3.hash(payload)); }

    /** 两个链节点的回答是否一致（from / 高度 / 确认时间 / payload）。 */
    public boolean sameAs(ChainTx o) {
        return o != null && txHash.equals(o.txHash) && chain.equals(o.chain) && from.equals(o.from)
                && assetId.equals(o.assetId) && height == o.height && confirmTimestamp == o.confirmTimestamp
                && java.util.Arrays.equals(payload, o.payload);
    }

    /** 解析 /v1/hash 响应。结构不符抛 IllegalArgumentException。 */
    public static ChainTx parse(String expectTxHash, byte[] body) {
        try {
            Map<String, Object> outer = StrictJson.parseObject(body);
            if (!StrictJson.bool(outer, "ok")) throw new IllegalArgumentException("ok=false");
            Map<String, Object> data = StrictJson.parseObject(StrictJson.str(outer, "data").getBytes(StandardCharsets.UTF_8));
            Map<String, Object> tx = StrictJson.parseObject(StrictJson.str(data, "tx").getBytes(StandardCharsets.UTF_8));
            String hash = StrictJson.str(tx, "txHash");
            if (expectTxHash != null && !expectTxHash.equals(hash))
                throw new IllegalArgumentException("txHash 不符：请求 " + expectTxHash + " 返回 " + hash);
            List<Object> arr = StrictJson.arr(tx, "payload");
            byte[] out = new byte[arr.size()];
            for (int i = 0; i < out.length; i++) {
                long v = (Long) arr.get(i);
                if (v < -128 || v > 255) throw new IllegalArgumentException("payload[" + i + "] 越界: " + v);
                out[i] = (byte) (v & 0xFF);
            }
            return new ChainTx(hash, StrictJson.str(tx, "chain"), StrictJson.str(tx, "from"), StrictJson.str(tx, "assetId"),
                    StrictJson.num(data, "height"), StrictJson.num(data, "confirmTimestamp"), out);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("交易响应结构不符: " + e.getMessage(), e);
        }
    }
}
