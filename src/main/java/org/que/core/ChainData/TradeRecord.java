package org.que.core.ChainData;

import org.que.crypto.CryptoUtil;

import java.io.*;
import java.util.Arrays;

// TradeRecord —— 交易：世界价值的流动
public final class TradeRecord extends AbstractQubeData {

    private String from;           // 发送方（null=系统发行）
    private String to;             // 接收方
    private String assetId;        // 资产标识：QU, BTC, 600519.SH, NFT#123
    private long   amount;         // 数量（最小单位）
    private String tradeType;      // transfer, mint, burn, swap, repay, stake...
    private String refId;          // 关联ID（如订单号、合约ID）


    // =============== 新建交易时使用（必须给合约地址） ===============
    public TradeRecord(String from, String to, String assetId, long amount,
                       String tradeType, String refId,
                       long feeAmount, byte[] pubKey, byte[] signature,
                       byte[] contractAddress) {

        super(ChainDataType.TRADE, feeAmount, pubKey, signature, contractAddress);

        this.from = from;
        this.to = to;
        this.assetId = assetId;
        this.amount = amount;
        this.tradeType = tradeType != null ? tradeType : "transfer";
        this.refId = refId;
    }


    // =============== 序列化 payload（不含头部） ===============
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


    // =============== 反序列化 payload ===============
    @Override
    protected void deserializePayload(DataInputStream dis) throws IOException {
        this.from = readString(dis);
        this.to = readString(dis);
        this.assetId = readString(dis);
        this.amount = dis.readLong();
        this.tradeType = readString(dis);
        this.refId = readString(dis);
    }


    // =============== 全局唯一 parseFrom（最硬核入口） ===============
    public static TradeRecord parseFrom(byte[] data) throws IOException {

        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));

        dis.readByte(); // typeId
        long ts = dis.readLong();
        long fee = dis.readLong();
        byte[] pubKey = readVarBytes(dis);
        byte[] sig = readVarBytes(dis);

        // ⭐ 保存原始 payloadHash
        byte[] hash = new byte[32];
        dis.readFully(hash);

        // ⭐ 正确顺序：contractAddress 必须在 payloadLen 前读取
        byte[] contractAddress = readVarBytes(dis);
        if (contractAddress.length == 0) {
            throw new IOException("TradeRecord 解析发现 contractAddress 为空！");
        }

        int len = dis.readInt();

        // ⭐ 创建对象（留空业务字段，稍后反序列化）
        TradeRecord r = new TradeRecord(
                null, null, null, 0,
                null, null,
                fee, pubKey, sig,
                contractAddress
        );

        r.setTimestamp(ts);
        r.originalPayloadHash = hash;  // ⭐ 必须保存，否则 verifyIntegrity 永远失败

        // ⭐ 解析 payload
        byte[] payload = new byte[len];
        dis.readFully(payload);

        r.deserializePayload(new DataInputStream(new ByteArrayInputStream(payload)));

        // ⭐ 验证完整性（子类内部 verifyIntegrity 使用 originalPayloadHash）
        if (!r.verifyIntegrity()) {
            throw new IOException("TradeRecord 完整性校验失败！数据可能被篡改！");
        }

        return r;
    }


    // =============== 完整性验证 ===============
    @Override
    public boolean verifyIntegrity() {
        try {
            byte[] currentPayload = serializePayload();
            byte[] currentHash = CryptoUtil.sha3256(currentPayload);

            return Arrays.equals(getOriginalPayloadHash(), currentHash);
        } catch (Exception e) {
            return false;
        }
    }


    // =============== 审计输出 ===============
    @Override
    public String toAuditString() {
        String fromShow = from == null ? "系统发行" : from.substring(0, Math.min(10, from.length()));
        return String.format("交易 [%s] %s → %s | %,d %s | 关联:%s",
                tradeType, fromShow, to.substring(0, Math.min(10, to.length())),
                amount, assetId, refId != null ? refId : "-");
    }


    // =============== JSON 输出 ===============
    @Override
    public String toJSON() {
        return String.format(
                "{\"type\":\"trade\",\"from\":\"%s\",\"to\":\"%s\",\"asset\":\"%s\",\"amount\":%d,\"tradeType\":\"%s\",\"ref\":\"%s\"}",
                from, to, assetId, amount, tradeType, refId);
    }


    // =============== Getter ===============
    public String getFrom() { return from; }
    public String getTo() { return to; }
    public String getAssetId() { return assetId; }
    public long getAmount() { return amount; }
    public String getTradeType() { return tradeType; }
    public String getRefId() { return refId; }
}
