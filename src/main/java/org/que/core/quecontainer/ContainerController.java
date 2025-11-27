package org.que.core.quecontainer;

import org.que.core.queBlock.QueBaseBlock;
import org.que.crypto.CryptoUtil;

import java.io.*;
import java.nio.charset.StandardCharsets;

public class ContainerController {

    private static final String DIR = "containers/";
    private static final long MAX_CONTAINER_SIZE = 5L * 1024 * 1024;  // 测试：5MB；主网换成200MB

    private static long currentContainerIndex = 1;
    private static File currentFile;
    private static BufferedWriter writer;

    private static String containerHash = "0";  // 容器内所有区块hash叠加

    static {
        init();
    }

    /** 初始化容器目录、当前容器文件 */
    private static void init() {
        File d = new File(DIR);
        if (!d.exists()) d.mkdirs();

        openNewContainer();
    }

    /** 创建新容器文件 */
    private static void openNewContainer() {
        closeCurrent();

        String filename = String.format("container_%06d.jsonl", currentContainerIndex++);
        currentFile = new File(DIR + filename);

        try {
            writer = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(currentFile, true), StandardCharsets.UTF_8
            ));
            System.out.println("■ 打开新容器文件: " + filename);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        containerHash = "0"; // 重置容器 hash
    }

    /** 关闭当前容器（写入容器foot） */
    private static void closeCurrent() {
        if (writer == null) return;

        try {
            writer.write("{\"containerFoot\": \"" + containerHash + "\"}\n");
            writer.flush();
            writer.close();
        } catch (Exception ignored) {}
    }

    /** 写入区块（JSON） */
    public synchronized static void write(QueBaseBlock block) {
        if (writer == null) openNewContainer();

        try {
            String json = block.toJson();
            writer.write(json);
            writer.write("\n");
            writer.flush();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // 更新容器哈希
        updateHash(block);

        // 检查容器大小
        rotateIfNeeded();
    }

    /** 叠加容器 hash */
    private static void updateHash(QueBaseBlock block) {
        containerHash = CryptoUtil.sha3256Hex(
                (containerHash + block.foot.blockHash)
                        .getBytes(StandardCharsets.UTF_8)
        );
    }

    /** 判断容器是否超出大小限制 */
    private static void rotateIfNeeded() {
        if (currentFile.length() >= MAX_CONTAINER_SIZE) {
            System.out.println("■ 容器已满，进行轮转...");
            openNewContainer();
        }
    }
}

