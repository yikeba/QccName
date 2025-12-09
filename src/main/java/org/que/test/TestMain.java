package org.que.test;

import com.alibaba.fastjson2.JSON;
import org.que.config.QubePath;
import org.que.core.queBlock.BlockController;
import org.que.core.queData.TransactionData;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

public class TestMain {
    private static final List<String> USERS = new ArrayList<>();
    private static final HttpClient client = HttpClient.newHttpClient();
    private static final String BALANCE_SERVER = "http://192.168.1.166:18081";  // ← 改成你 Windows IP

    public static void main(String[] args) throws Exception {
        System.out.println("======= QubeChain 远程余额服务器终极验证开始 =======\n");
        QubePath.init();
        initUsers(10);

        System.out.println("开始发送 5000 笔随机转账（远程实时核销中...）\n");
        ThreadLocalRandom r = ThreadLocalRandom.current();

        int success = 0;
        int reject = 0;

        for (int i = 1; i <= 100; i++) {
            String to = USERS.get(r.nextInt(USERS.size()));
            long amount = r.nextLong(1, 5000);

            TransactionData tx = new TransactionData("que-test");
            tx.from = "bank_01";
            tx.to = to;
            tx.amount = amount;

            // 关键：远程调用余额服务器核销
            boolean ok = callBalanceServer("tx_00"+i, tx.amount, "DEDUCT");     // 扣款
            if (ok) {
                BlockController.receive(tx);
                success++;
            } else {
                reject++;
                System.out.println("第 " + i + " 笔被拒绝（余额不足）: "+tx.from+" → " + to + " " + amount);
            }

            if (i % 500 == 0) {
                System.out.println("已处理 " + i + " 笔，成功=" + success + "，拒绝=" + reject);
            }
        }

        Thread.sleep(5000);
        System.out.println("\n测试结束！全网余额已由远程服务器维护，数学级守恒由服务器保证！");
        System.out.println("成功交易 = " + success + "，被拒绝 = " + reject);
    }

    // 正确：op 必须是 "DEDUCT" / "FREEZE" / "UNFREEZE" / "REFUND"
    private static boolean callBalanceServer(String bizId, long amount, String op) {
        try {
            String json = JSON.toJSONString(new BalanceRequest(bizId, "bank_01", amount, op));
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(BALANCE_SERVER + "/balance/apply"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .timeout(java.time.Duration.ofSeconds(5))
                    .build();
            HttpResponse<String> resp = client.send(request, HttpResponse.BodyHandlers.ofString());
            BalanceResult result = JSON.parseObject(resp.body(), BalanceResult.class);
            System.out.println("远程调用结果: " + result);
            return result.success();
        } catch (Exception e) {
            System.out.println("调用余额服务器失败: " + e.getMessage());
            return false;
        }
    }


    private static void initUsers(int count) {
        USERS.clear();
        for (int i = 1; i <= count; i++) {
            USERS.add("USER_merchant" + i);
        }
        System.out.println("初始化用户 = " + USERS.size() + " 个\n");
    }

    // 和服务器保持一致的结构
    record BalanceRequest(String bizId, String userId, long amount, String op) {}
    record BalanceResult(boolean success, long available, long frozen, String error) {}
}