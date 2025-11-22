package org.example.core;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import java.util.concurrent.CopyOnWriteArrayList;

@Component  // 自动注入，像Android @Inject一样
public class ContainerManager {

    private long currentContainerId = 0;
    private String prevHash = "qube-genesis-2025";
    private final CopyOnWriteArrayList<String> currentTxs = new CopyOnWriteArrayList<>();

    // 每10分钟自动执行一次（跟Android AlarmManager一样）
    @Scheduled(fixedDelay = 600000)  // 600000ms = 10分钟
    public void sealContainer() {
        String sealedHash = prevHash + "|txs:" + currentTxs.size() + "|time:" + System.currentTimeMillis();
        sealedHash = java.util.Base64.getEncoder().encodeToString(sealedHash.getBytes()); // 简化哈希

        System.out.println("\n容器 " + currentContainerId + " 已关闭！共 " + currentTxs.size() + " 笔交易");
        System.out.println("最终哈希: " + sealedHash.substring(0, 32) + "... 转为冷数据\n");

        // 新容器诞生
        prevHash = sealedHash;
        currentContainerId++;
        currentTxs.clear();

        System.out.println("新容器 " + currentContainerId + " 已启动！继承脊柱哈希");
    }

    // fChat调用这个方法上链（就像调用startService()）
    public void submitSales(String merchantId, double amount) {
        String tx = "SALES|" + merchantId + "|" + amount + "|" + System.currentTimeMillis();
        currentTxs.add(tx);
        System.out.println("容器 " + currentContainerId + " 收到销售上链: " + tx);
    }

    public long getCurrentContainerId() {
        return currentContainerId;
    }
}