package org.que.core.queData;


import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.annotation.JSONField;
import com.alibaba.fastjson2.annotation.JSONType;


@JSONType(typeName = "transaction")   // 关键第1行
public class TransactionData extends QueBaseData {

    private static final String TYPE = "transaction";

    @JSONField(ordinal = 7)
    public String to;

    @JSONField(ordinal = 8)
    public long amount;

    @JSONField(ordinal = 9)
    public String memo;

    public TransactionData(String contractAddress) {
        initBaseFields(contractAddress);
    }

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public String getPayloadForHash() {
        return id + "|" + contractAddress + "|" + from + "|" + to + "|" + amount +
                "|" + (memo == null ? "" : memo);
    }

/*    public boolean verify(LocalBalanceSnapshot snapshot) {
        long balance = snapshot.getBalance(from);
        if (balance < amount) {
            System.err.println("[TX] 余额不足: from=" + from +
                    " need=" + amount + " actual=" + balance);
            return false;
        }
        snapshot.update(from, -amount);
        snapshot.update(to,   +amount);
        return true;

    }*/

    public String toJsonString() {
        return JSON.toJSONString(this);
    }
}
