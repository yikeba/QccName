package org.que.test;

import org.que.config.QubePath;
import org.que.core.queBlock.QueBaseBlock;
import org.que.core.queData.QueBaseData;
import org.que.core.queData.TransactionData;
import org.que.core.quecontainer.QueBaseContainer;
import org.que.core.quecontainer.QueContainerReader;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class TestLoad {

    public static void main(String[] args) throws Exception {
         loadContainers();
    }

    private static List<QueBaseContainer> loadContainers() throws Exception {
        List<QueBaseContainer> list = new ArrayList<>();
        Path dir = QubePath.CONTAINER_DIR;

        if (!Files.exists(dir)) return list;
        long maxamount=0;
        int index=0;
        for (Path p : Files.newDirectoryStream(dir, "*.que")) {

            QueContainerReader c = QueContainerReader.load(p);
            for (QueBaseBlock block : c.getAllBlocks()) {
                if (block.body == null) continue;
                for (QueBaseData d : block.body.dataList) {
                    if (d instanceof TransactionData tx) {
                        // map.merge(tx.from, -tx.amount, Long::sum);
                        // map.merge(tx.to, tx.amount, Long::sum);
                        System.out.println(tx.from+":"+tx.amount+"   to:"+tx.to+"   ");
                        maxamount=maxamount+tx.amount;
                        index++;
                    }
                }
            }


        }
        System.out.println("总计转账amount:"+maxamount+"   笔数："+index);
        return list;
    }
    private static void showboyd(QueBaseContainer c) {

        for (QueBaseBlock block : c.blocks) {
            if (block.body == null) continue;
            for (QueBaseData d : block.body.dataList) {
                if (d instanceof TransactionData tx) {
                    // map.merge(tx.from, -tx.amount, Long::sum);
                    // map.merge(tx.to, tx.amount, Long::sum);
                    System.out.println(tx.from+":"+tx.amount+"   to:"+tx.to);
                }
            }
        }
    }

}
