package org.que.test;

import org.que.config.QubePath;
import org.que.core.queBlock.QueBaseBlock;
import org.que.core.queData.QueBaseData;
import org.que.core.queData.TransactionData;
import org.que.core.quecontainer.QueBaseContainer;
import org.que.core.quecontainer.QueContainerReader;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ContainerBalanceReplayTest {

    public static void main(String[] args) throws Exception {
        // 1. 初始化路径，找到容器目录
        QubePath.init();
        Path dir = QubePath.CONTAINER_DIR;
        System.out.println("容器目录 = " + dir.toAbsolutePath());

        // 2. 扫描所有 .que 容器
        List<Path> files;
        try (Stream<Path> s = Files.list(dir)) {
            files = s.filter(p -> p.toString().endsWith(".que"))
                    .sorted()
                    .collect(Collectors.toList());
        }

        System.out.println("发现容器文件数量 = " + files.size());

        // 3. 用一个 map 重新计算余额（只看本次容器里的净变化）
        Map<String, Long> delta = new HashMap<>();

        long txCount = 0;
        for (Path p : files) {
            QueBaseContainer c = QueContainerReader.read(p);
            if (c == null || c.blocks == null) continue;

            for (QueBaseBlock block : c.blocks) {
                if (block.body == null || block.body.dataList == null) continue;

                for (QueBaseData d : block.body.dataList) {
                    if (d instanceof TransactionData tx) {
                        txCount++;
                        // from 扣钱
                        delta.merge(tx.from, -tx.amount, Long::sum);
                        // to 加钱
                        delta.merge(tx.to, tx.amount, Long::sum);
                    }
                }
            }
        }

        System.out.println("从容器重放出的交易条数 = " + txCount);

        // 4. 打印每个用户的净变化（你可以自己加上初始 1,000,000）
        System.out.println("=========== 容器重放后的余额变化(Δ) ===========");
        List<String> keys = new ArrayList<>(delta.keySet());
        Collections.sort(keys);

        long total = 0;
        for (String addr : keys) {
            long d = delta.getOrDefault(addr, 0L);
            total += d;
            System.out.println(addr + " 变动 = " + d);
        }
        System.out.println("--------------------------------------");
        System.out.println("所有地址 Δ 之和 = " + total + "（应该为 0）");
    }
}
