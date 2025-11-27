package org.que.core.ChainData;

import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;
import org.que.crypto.CryptoUtil;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * RuleRecord —— 数字世界的“法律、合同、规则、宣告”
 * 用途：发票、电子合同、保险保单、DAO提案、政府公告、许可证、合规声明...
 */
public final class RuleRecord extends AbstractQubeData {

    // ==================== 业务字段 ====================
    private String ruleType;                  // 规则类型：invoice, contract, announcement, dao_proposal...
    private String title;                     // 标题（如：销项发票#2025001）
    private String contentHash;               // 大文本内容哈希（推荐存IPFS: ipfs://Qm...）
    private long effectiveTime;               // 生效时间（毫秒）
    private long expireTime;                  // 过期时间（0 = 永久有效）
    private List<String> parties;             // 参与方地址列表（如甲方、乙方、监管方）

    // ==================== 构造器：创建新规则 ====================
    public RuleRecord(String ruleType,
                      String title,
                      String contentHash,
                      long effectiveTime,
                      long expireTime,
                      List<String> parties,
                      long feeAmount,
                      byte[] senderPubKey,
                      byte[] signature,
                      byte[] contractAddress
                      ) {

        super(ChainDataType.RULE, feeAmount, senderPubKey, signature,contractAddress);

        this.ruleType = ruleType != null ? ruleType : "custom";
        this.title = title != null ? title : "";
        this.contentHash = contentHash;
        this.effectiveTime = effectiveTime;
        this.expireTime = expireTime;
        this.parties = parties != null ? new ArrayList<>(parties) : new ArrayList<>();
    }

    // ==================== 序列化：业务字段 → byte[] ====================
    @Override
    protected byte[] serializePayload() throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(baos)) {

            writeString(dos, ruleType);
            writeString(dos, title);
            writeString(dos, contentHash);
            dos.writeLong(effectiveTime);
            dos.writeLong(expireTime);

            // 写入参与方列表
            dos.writeInt(parties.size());
            for (String party : parties) {
                writeString(dos, party);
            }

            return baos.toByteArray();
        }
    }

    // ==================== 反序列化：byte[] → 业务字段 ====================
    @Override
    protected void deserializePayload(DataInputStream dis) throws IOException {
        this.ruleType = readString(dis);
        this.title = readString(dis);
        this.contentHash = readString(dis);
        this.effectiveTime = dis.readLong();
        this.expireTime = dis.readLong();

        // 读取参与方列表
        int partyCount = dis.readInt();
        this.parties = new ArrayList<>(partyCount);
        for (int i = 0; i < partyCount; i++) {
            this.parties.add(readString(dis));
        }
    }

    // ==================== 全局唯一 parseFrom（最硬核入口） ====================
    public static RuleRecord parseFrom(byte[] data) throws IOException {
        if (data == null || data.length < 60) throw new IOException("RuleRecord 数据太短");

        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));

        dis.readByte();  // typeId
        long timestamp = dis.readLong();
        long feeAmount = dis.readLong();
        byte[] pubKey = readVarBytes(dis);
        byte[] signature = readVarBytes(dis);

        // ⭐ 保存 payloadHash 到父类字段 originalPayloadHash
        byte[] hash = new byte[32];
        dis.readFully(hash);

        // ⭐ 正确顺序：contractAddress MUST be here
        byte[] contractAddress = readVarBytes(dis);
        if (contractAddress.length == 0) {
            throw new IOException("反序列化时发现 contractAddress 为空！");
        }

        int payloadLen = dis.readInt();

        RuleRecord record = new RuleRecord(
                null, null, null,
                0, 0,
                null,
                feeAmount,
                pubKey,
                signature,
                contractAddress
        );

        record.setTimestamp(timestamp);
        record.originalPayloadHash = hash; // ⭐ 必须补上

        byte[] payload = new byte[payloadLen];
        dis.readFully(payload);
        record.deserializePayload(new DataInputStream(new ByteArrayInputStream(payload)));

        return record;
    }


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
    // ==================== toAuditString：审计灵魂（必须！） ====================
    @Override
    public String toAuditString() {
        String status = (expireTime > 0 && System.currentTimeMillis() > expireTime) ? "已过期" : "有效";
        return String.format("规则 [%s] 《%s》 | 参与方:%d | 生效:%tc | 状态:%s | 内容:%s",
                ruleType,
                title.length() > 20 ? title.substring(0, 20) + "..." : title,
                parties.size(),
                new java.util.Date(effectiveTime),
                status,
                contentHash != null && contentHash.startsWith("ipfs://") ? contentHash : "链上存储");
    }

    // ==================== toJSON：前端/浏览器专用 ====================
    @Override
    public String toJSON() {
        JSONObject json = new JSONObject();
        json.put("type", "rule");
        json.put("ruleType", ruleType);
        json.put("title", title);
        json.put("contentHash", contentHash);
        json.put("effectiveTime", effectiveTime);
        json.put("expireTime", expireTime);
        json.put("parties", parties);
        json.put("status", expireTime > 0 && System.currentTimeMillis() > expireTime ? "expired" : "active");
        return json.toJSONString(JSONWriter.Feature.PrettyFormat);
    }

    // ==================== Getter ====================
    public String getRuleType() { return ruleType; }
    public String getTitle() { return title; }
    public String getContentHash() { return contentHash; }
    public List<String> getParties() { return new ArrayList<>(parties); }
}