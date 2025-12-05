package org.que.api;

import org.que.core.queBlock.QueBaseBlock;
import org.que.core.queData.QueBaseData;
import org.que.core.queData.TransactionData;
import org.que.core.quecontainer.QueContainerReader;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class TransactionQueryAPI {

    private final Path containerDir;

    public TransactionQueryAPI(Path containerDir) {
        this.containerDir = containerDir;
    }

    public List<TransactionData> listTransactions(String address) throws Exception {
        List<TransactionData> result = new ArrayList<>();

        try (var stream = Files.list(containerDir)) {
            for (Path p : stream.toList()) {

                if (!p.toString().endsWith(".que")) continue;
                // 优化：使用 BloomFilter 判断是否有可能包含该地址
                QueContainerReader reader = QueContainerReader.load(p);
                if (!reader.mightContainAddress(address)) continue;
                // 精确检查每个 block
                for (QueBaseBlock block : reader.getAllBlocks()) {
                    for (QueBaseData data : block.body.dataList) {
                        if (data instanceof TransactionData tx) {
                            if (tx.from.equals(address) || tx.to.equals(address)) {
                                result.add(tx);
                            }
                        }
                    }
                }
            }
        }

        return result;
    }
}
