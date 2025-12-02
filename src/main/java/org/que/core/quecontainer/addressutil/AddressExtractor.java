package org.que.core.quecontainer.addressutil;


import org.bouncycastle.util.encoders.Hex;
import org.que.core.queBlock.QueBaseBlock;
import org.que.core.queData.EntityData;
import org.que.core.queData.QueBaseData;
import org.que.core.queData.RuleData;
import org.que.core.queData.TransactionData;
import org.que.util.Base58;
import org.que.util.ToolsUtil;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class AddressExtractor {

    public static Set<String> collectAddressHash160(List<QueBaseBlock> blocks) {
        Set<String> set = new HashSet<>();

        for (QueBaseBlock block : blocks) {
            if (block == null || block.body == null || block.body.dataList == null)
                continue;

            for (QueBaseData d : block.body.dataList) {

                // Transaction
                if (d.from != null) {
                    set.add(toHash160Hex(d.from));
                }
                if (d instanceof TransactionData tx) {
                    if (tx.to != null) {
                        set.add(toHash160Hex(tx.to));
                    }
                }

                // EntityData
                if (d instanceof EntityData e) {
                    if (e.owner != null) {
                        set.add(toHash160Hex(e.owner));
                    }
                }

                // RuleData
                if (d instanceof RuleData r) {
                    // 如果未来 rule 有 owner，可以在这里加
                }
            }
        }

        return set;
    }

    /** 地址 → Hash160(hex) */
    public static String toHash160Hex(String address) {
        String base58 = address.substring(1); // 去掉 Q 前缀
        byte[] raw = Base58.decode(base58);

        // version(1) + hash160(20) + checksum(4)
        byte[] hash160 = new byte[20];
        System.arraycopy(raw, 1, hash160, 0, 20);

        return Hex.toHexString(hash160);
    }
}
