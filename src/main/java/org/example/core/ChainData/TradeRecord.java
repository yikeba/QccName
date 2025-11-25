package org.example.core.ChainData;

import org.example.crypto.CryptoUtil;

import java.io.*;
import java.util.Arrays;

// TradeRecord.java —— 交易：世界价值的流动
public final class TradeRecord extends AbstractQubeData {

    private String from;           // 发送方（null=系统发行）
    private String to;             // 接收方
    private String assetId;        // 资产标识：QU, BTC, 600519.SH, NFT#123
    private long   amount;         // 数量（最小单位）
    private String tradeType;      // transfer, mint, burn, swap, repay, stake...
    private String refId;          // 关联ID（如订单号、合约ID）

    public TradeRecord(String from, String to, String assetId, long amount,
                       String tradeType, String refId,
                       long feeAmount, byte[] pubKey, byte[] signature) {
        super(ChainDataType.TRADE, feeAmount, pubKey, signature);
        this.from = from;
        this.to = to;
        this.assetId = assetId;
        this.amount = amount;
        this.tradeType = tradeType != null ? tradeType : "transfer";
        this.refId = refId;
    }

    @Override
    protected byte[] serializePayload() throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(baos)) {
            writeString(dos, from);
            writeString(dos, to);
            writeString(dos, assetId);
            dos.writeLong(amount);
            writeString(dos, tradeType);
            writeString(dos, refId);
            return baos.toByteArray();
        }
    }


    @Override
    protected void deserializePayload(DataInputStream dis) throws IOException {
        this.from = readString(dis);
        this.to = readString(dis);
        this.assetId = readString(dis);
        this.amount = dis.readLong();
        this.tradeType = readString(dis);
        this.refId = readString(dis);
    }

    public static TradeRecord parseFrom(byte[] data) throws IOException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
        dis.readByte(); // typeId
        long ts = dis.readLong();
        long fee = dis.readLong();
        byte[] pubKey = readVarBytes(dis);
        byte[] sig = readVarBytes(dis);
        dis.readNBytes(32); // hash
        int len = dis.readInt();

        TradeRecord r = new TradeRecord(null, null, null, 0, null, null, fee, pubKey, sig);
        r.setTimestamp(ts);
        r.deserializePayload(new DataInputStream(new ByteArrayInputStream(dis.readNBytes(len))));
        // 立即校验！不通过直接抛异常
        if (!r.verifyIntegrity()) {
            throw new IOException("TradeRecord 完整性校验失败！数据被篡改或解析错误！");
        }
        return r;
    }

    // TradeRecord.java
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

    @Override
    public String toAuditString() {
        String fromShow = from == null ? "系统发行" : from.substring(0, Math.min(10, from.length()));
        return String.format("交易 [%s] %s → %s | %,d %s | 关联:%s",
                tradeType, fromShow, to.substring(0, Math.min(10, to.length())),
                amount, assetId, refId != null ? refId : "-");
    }

    @Override
    public String toJSON() {
        return String.format(
                "{\"type\":\"trade\",\"from\":\"%s\",\"to\":\"%s\",\"asset\":\"%s\",\"amount\":%d,\"tradeType\":\"%s\",\"ref\":\"%s\"}",
                from, to, assetId, amount, tradeType, refId);
    }

    public String getFrom() { return from; }
    public String getTo() { return to; }
    public String getAssetId() { return assetId; }
    public long getAmount() { return amount; }
    public String getTradeType() { return tradeType; }
    public String getRefId() { return refId; }
}