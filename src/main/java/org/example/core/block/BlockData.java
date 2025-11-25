package org.example.core.block;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONWriter;
import org.example.core.ChainData.*;
import org.example.core.ChainData.TradeRecord;

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

    // ====================== 2. 流式添加记录（生产核心！）======================
    public synchronized void addRecord(AbstractQubeData record) {
        if (sealed) throw new IllegalStateException("BlockData 已封块，不可添加");
        if (record == null) throw new IllegalArgumentException("记录不能为 null");
        try {
            byte[] bytes = record.toByteArray();
            rawBytes.writeBytes(bytes);
            // 收集地址
            involvedAddresses.add(record.getSenderPubKey());
            if (record instanceof TradeRecord trade) {
                String to = trade.getTo();
                if (to != null && !to.isEmpty()) {
                    involvedAddresses.add(to.getBytes(StandardCharsets.UTF_8));
                }
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
    private List<AbstractQubeData> parseRecordsFromRaw() {
        byte[] data = rawBytes.toByteArray();
        List<AbstractQubeData> list = new ArrayList<>();
        int offset = 0;
        try {
            while (offset < data.length) {
                AbstractQubeData record = AbstractQubeData.parseFrom(
                        Arrays.copyOfRange(data, offset, data.length)
                );
                list.add(record);
                offset += record.toByteArray().length;
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


    // 正确写法！（你赢了！）
    public void loadFromBytes(byte[] rawBytes) throws IOException {
        if (sealed) throw new IllegalStateException("已封块不能加载");
        if (rawBytes == null || rawBytes.length == 0) return;

        int offset = 0;
        while (offset < rawBytes.length) {
            AbstractQubeData record = AbstractQubeData.parseFrom(
                    Arrays.copyOfRange(rawBytes, offset, rawBytes.length)
            );
            this.addRecord(record);  // 直接用 this！
            offset += record.toByteArray().length;
        }
    }
}