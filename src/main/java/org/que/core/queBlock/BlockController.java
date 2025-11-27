package org.que.core.queBlock;

import org.que.core.queData.QueBaseData;
import org.que.core.quecontainer.ContainerController;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;

public class BlockController {

    // 数据队列（无限容量，线程安全）
    private static final LinkedBlockingQueue<QueBaseData> queue = new LinkedBlockingQueue<>();

    private static final long BLOCK_INTERVAL_MS = 3000;

    private static long blockHeight = 0;
    private static String lastBlockHash = "GENESIS";

    static {
        startBlockEngine();
    }

    /** 数据接收入口（任何来源的数据最终都到这里） */
    public static void receive(QueBaseData data) {
        queue.offer(data);  // 放入队列
    }

    /** 启动区块引擎（独立线程、每3秒执行一次） */
    private static void startBlockEngine() {
        Thread t = new Thread(() -> {
            while (true) {
                try { Thread.sleep(BLOCK_INTERVAL_MS); } catch (InterruptedException ignored) {}

                buildNextBlock();
            }
        });

        t.setDaemon(true);
        t.start();
    }

    /** 构建下一个区块 */
    private static synchronized void buildNextBlock() {

        List<QueBaseData> list = new ArrayList<>();
        queue.drainTo(list);   // 取出全部待处理数据

        if (list.isEmpty()) return;

        long height = ++blockHeight;

        QueBaseBlock block =
                new QueBaseBlock(height, "1.0.0", lastBlockHash);

        for (QueBaseData d : list) {
            block.addData(d);
        }

        block.build();

        lastBlockHash = block.foot.blockHash;

        // 交给容器
        ContainerController.write(block);

        System.out.println("出块 #" + height + "，数据量=" + list.size());
    }
}

