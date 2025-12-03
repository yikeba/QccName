package org.que.core.queBlock;

import org.que.core.cache.BalanceServer;
import org.que.core.cache.LocalBalanceSnapshot;
import org.que.core.cache.MemoryBalanceServer;
import org.que.core.queData.QueBaseData;
import org.que.core.queData.TransactionData;
import org.que.core.quecontainer.ContainerManager;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

public class BlockController {

    private static final LinkedBlockingQueue<QueBaseData> queue = new LinkedBlockingQueue<>();
    private static final long BLOCK_INTERVAL_MS = 3000;

    private static final AtomicLong blockHeight = new AtomicLong(0);
    private static final String GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";
    private static volatile String lastBlockHash = GENESIS_HASH;

    static {
        startBlockEngine();
    }

    public static void receive(QueBaseData data) {
        queue.offer(data);
    }

    private static void startBlockEngine() {
        Thread t = new Thread(() -> {
            while (true) {
                try {
                    List<QueBaseData> list = new ArrayList<>();
                    QueBaseData first = queue.poll(2900, java.util.concurrent.TimeUnit.MILLISECONDS);
                    if (first != null) {
                        list.add(first);
                        queue.drainTo(list);  // 再把剩下的全取出来
                    }

                    if (!list.isEmpty()) {
                        buildNextBlock(list);
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });
        t.setDaemon(true);
        t.setName("QubeBlockEngine");
        t.start();
    }

    public static int getQueueSize() {
        return queue.size();
    }

    private static final MemoryBalanceServer balanceServer = new MemoryBalanceServer();
    private static final LocalBalanceSnapshot snapshot =
            new LocalBalanceSnapshot(balanceServer);


    private static synchronized void buildNextBlock(List<QueBaseData> list) {
        long height = blockHeight.incrementAndGet();

        QueBaseBlock block = new QueBaseBlock(height, "1.0.0", lastBlockHash);

        for (QueBaseData d : list) {
            // 交易验证
            if (d instanceof TransactionData tx) {
                if (!tx.verify(snapshot)) {
                    System.err.println("[BlockEngine] 拒绝交易: from="
                            + tx.from + " amount=" + tx.amount);
                    continue;
                }else{
                    System.err.println("[BlockEngine] 批准交易: from="
                            + tx.from + " amount=" + tx.amount);
                }
            }
            // 验证通过 → 写入区块
            block.addData(d);
        }

        block.build();

        lastBlockHash = block.foot.blockHash;

        ContainerManager.appendBlock(block);

        System.out.println("出块 #" + height +
                " 数据量=" + block.body.dataList.size() +
                " blockHash=" + block.foot.blockHash.substring(0, 16));
    }

    // 程序关闭时强制刷盘
    public static void shutdown() {
        ContainerManager.close();
    }
}