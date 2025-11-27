package org.que.core.block;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONWriter;
import org.que.core.ChainData.*;
import org.que.core.ChainData.TradeRecord;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * BlockData v14 - 真正的生产级流式数据区
 * 支持：addRecord() → 流式添加 → 封块前可控 → 封块后不可变
 */
public final class BlockData implements Serializable {

    @java.io.Serial
    private static final long serialVersionUID = 20251125L;

    // 封块后才填充：内存态记录列表（用于查询）
    private volatile List<AbstractQubeData> records = null;

    // 始终维护：原始字节（落盘用）
    private final ByteArrayOutputStream rawBytes;

    // 始终维护：地址集合（封块后提交索引）
    private final Set<byte[]> involvedAddresses;

    // 封块状态
    private volatile boolean sealed = false;

    // 私有构造器
    private BlockData() {
        this.rawBytes = new ByteArrayOutputStream();
        this.involvedAddresses = new HashSet<>();
    }

    // ====================== 1. 工厂：创建空的 BlockData ======================
    public static BlockData createEmpty() {
        return new BlockData();
    }

    public synchronized void addRecord(AbstractQubeData record) {
        if (sealed) throw new IllegalStateException("BlockData 已封块，不可添加");
        try {
            byte[] wrapped = record.toRecordBytes();  // ⭐ 包含长度字段
            rawBytes.writeBytes(wrapped);

            involvedAddresses.add(record.getSenderPubKey());
            if (record instanceof TradeRecord t && t.getTo() != null) {
                involvedAddresses.add(t.getTo().getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ====================== 3. 封块（不可逆操作）======================
    public synchronized void seal() {
        if (sealed) return;
        sealed = true;
        // 封块后才解析出 records（节省内存）
        this.records = parseRecordsFromRaw();
    }

    // ====================== 4. 解析原始字节为记录对象（封块后调用）======================
    // ====================== 4. 解析原始字节为记录对象（封块后调用）======================
    private List<AbstractQubeData> parseRecordsFromRaw() {

        byte[] data = rawBytes.toByteArray();
        List<AbstractQubeData> list = new ArrayList<>();

        int offset = 0;
        try {
            while (offset < data.length) {

                // 1. 先读取记录长度（4 字节 int）
                int recLen = ((data[offset] & 0xFF) << 24)
                        | ((data[offset+1] & 0xFF) << 16)
                        | ((data[offset+2] & 0xFF) << 8)
                        |  (data[offset+3] & 0xFF);

                if (recLen <= 0 || recLen > data.length) {
                    throw new IOException("记录长度异常: " + recLen);
                }

                offset += 4;  // 跳过长度字段

                // 2. 读取该记录的完整内容（toByteArray 结果）
                byte[] recordBytes = Arrays.copyOfRange(data, offset, offset + recLen);

                // 3. 用 QubeDataFactory 来解析，一次性完成所有映射
                AbstractQubeData record = QubeDataFactory.parse(recordBytes);

                list.add(record);

                // 4. 指针移动到下一条记录
                offset += recLen;
            }

        } catch (Exception e) {
            throw new RuntimeException("封块后解析记录失败", e);
        }

        return List.copyOf(list);
    }


    // ====================== 5. 状态判断 ======================
    public boolean isSealed() { return sealed; }
    public int getRecordCount() { return sealed ? records.size() : -1; }
    public int getSizeInBytes() { return rawBytes.size(); }
    public boolean isEmpty() { return rawBytes.size() == 0; }

    // ====================== 6. 封块后才允许访问 ======================
    public List<AbstractQubeData> getRecords() {
        if (!sealed) throw new IllegalStateException("未封块");
        return records;
    }

    public byte[] getRawBytes() {
        if (!sealed) return rawBytes.toByteArray().clone();
        return rawBytes.toByteArray().clone();
    }

    public Set<byte[]> getInvolvedAddresses() {
        return Set.copyOf(involvedAddresses);
    }

    // ====================== 7. 可视化（封块后）======================
    public String toJson() {
        if (!sealed) return "{\"status\":\"unsealed\",\"size\":" + rawBytes.size() + "}";
        JSONArray arr = new JSONArray();
        for (AbstractQubeData r : records) {
            arr.add(com.alibaba.fastjson2.JSONObject.parseObject(r.toJSON()));
        }
        return arr.toJSONString(JSONWriter.Feature.PrettyFormat);
    }

    public String toAuditString() {
        if (!sealed) {
            return String.format("Data[未封块 | %d bytes | 地址:%d]", rawBytes.size(), involvedAddresses.size());
        }
        long trade = records.stream().filter(r -> r.getType() == ChainDataType.TRADE).count();
        long rule  = records.stream().filter(r -> r.getType() == ChainDataType.RULE).count();
        long entity = records.stream().filter(r -> r.getType() == ChainDataType.ENTITY).count();
        return String.format("Data[%d 条 | 交易:%d | 规则:%d | 实体:%d | %d bytes | 地址:%d]",
                records.size(), trade, rule, entity, rawBytes.size(), involvedAddresses.size());
    }

    @Override
    public String toString() { return toAuditString(); }


    public void loadFromBytes(byte[] bytes) throws IOException {
        records.clear();

        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bytes));

        while (dis.available() > 0) {

            // ⭐ 读取记录长度（固定4字节）
            int len = dis.readInt();
            if (len <= 0 || len > bytes.length) {
                throw new IOException("检测到非法记录长度: " + len);
            }

            // ⭐ 读取该记录对应的完整 toByteArray()
            byte[] recBytes = new byte[len];
            dis.readFully(recBytes);

            // ⭐ 核心：用工厂解析，而不是 AbstractQubeData.parseFrom()
            AbstractQubeData record = QubeDataFactory.parse(recBytes);

            records.add(record);
        }
    }


}