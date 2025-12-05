package org.que.test;

import org.que.core.cache.MemoryBalanceServer;
import org.que.core.cache.BalanceServer;
import org.que.core.queBlock.BlockController;
import org.que.core.queData.TransactionData;

import java.util.*;

public class Test1000Transactions {

    private static final int USER_COUNT = 30;
    private static final int TX_COUNT = 100000;
    private static final long INIT_BALANCE = 1_000_000L;

    static List<String> users = new ArrayList<>();

    private static MemoryBalanceServer getMemoryBalanceServer() {
        try {
            var field = BlockController.class.getDeclaredField("balanceServer");
            field.setAccessible(true);
            return (MemoryBalanceServer) field.get(null);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void initUsers() {
        MemoryBalanceServer server = getMemoryBalanceServer();

        for (int i = 1; i <= USER_COUNT; i++) {
            String u = "USER_" + i;
            users.add(u);
            server.initBalance(u, INIT_BALANCE);
        }

        System.out.println("初始化余额完成，每个用户 = " + INIT_BALANCE);
    }

    public static void main(String[] args) throws Exception {

        System.out.println("启动 100000 笔随机交易压测…");

        initUsers();

        Random random = new Random();
        long start = System.currentTimeMillis();

        for (int i = 1; i <= TX_COUNT; i++) {

            String from;
            String to;

            // 随机选用户（不能相同）
            while (true) {
                from = users.get(random.nextInt(users.size()));
                to = users.get(random.nextInt(users.size()));
                if (!from.equals(to)) break;
            }

            // 随机金额：1~500
            long amount = 1 + random.nextInt(500);

            // 构造交易
            TransactionData tx = new TransactionData("que");
            tx.from = from;
            tx.to = to;
            tx.amount = amount;

            // 注入区块控制器
            BlockController.receive(tx);

            if (i % 100 == 0) {
                System.out.println("已发送随机交易=" + i);
            }
        }

        // 等待至少两个出块周期（6 秒）
        Thread.sleep(6000);

        MemoryBalanceServer server = getMemoryBalanceServer();

        System.out.println("\n=========== 最终余额 ===========");

        long total = 0;
        for (String u : users) {
            long bal = server.getBalance(u);
            total += bal;
            System.out.println(u + " ：" + bal);
        }

        System.out.println("--------------------------------------");
        System.out.println("余额总和 = " + total +
                "（理论总和 = " + (INIT_BALANCE * USER_COUNT) + "）");
        System.out.println("差额 = " +
                (total - (INIT_BALANCE * USER_COUNT)));
        System.out.println("耗时 = " +
                (System.currentTimeMillis() - start) + " ms");
        System.out.println("--------------------------------------");

        System.out.println("区块和容器已全部写入（可检查 .que 文件）");
    }
}
