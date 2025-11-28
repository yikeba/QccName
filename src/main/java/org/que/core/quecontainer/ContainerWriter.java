package org.que.core.quecontainer;

import org.que.config.QubePath;
import org.que.core.queBlock.QueBaseBlock;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * 容器物理写入适配器：
 * - 负责构造 QueContainerHead
 * - 调用 QueContainerWriter 写 JSON
 * - 最终把文件重命名为 {tailHash}.que
 */
public class ContainerWriter {

    // 使用全局统一路径：~/qubechain/containers
    private static final Path DIR = QubePath.CONTAINER_DIR;

    static {
        try {
            QubePath.init();              // 确保根目录准备好
            Files.createDirectories(DIR); // 再次确保 containers 目录存在
        } catch (Exception e) {
            throw new RuntimeException("初始化 ContainerWriter 目录失败: " + DIR, e);
        }
    }

    /**
     * 写入一个完整容器：
     *  - containerNumber：逻辑编号（用于 head.containerNumber）
     *  - prevContainerHash：前一个容器的 tailHash
     *  - blocks：本容器包含的区块列表
     *
     * 返回：QueBaseContainer（包含 head + indexList + tailHash）
     */
    public static QueBaseContainer writeContainer(
            long containerNumber,
            String prevContainerHash,
            List<QueBaseBlock> blocks
    ) {
        try {
            // head
            QueContainerHead head = new QueContainerHead(
                    UUID.randomUUID().toString().replace("-", ""),
                    "QUBE_MAIN",
                    containerNumber,
                    prevContainerHash,
                    "1.0.0"
            );

            // 目录
            Path dir = QubePath.CONTAINER_DIR;
            Files.createDirectories(dir);

            // 临时文件（稳定固定命名）
            Path tempFile = dir.resolve(String.format("container_%06d.tmp", containerNumber));

            // 先写入临时文件
           // QueBaseContainer c = QueContainerWriter.writeContainer(head, blocks, tempFile.toFile());

            try {
                QueBaseContainer c = QueContainerWriter.writeContainer(head, blocks, tempFile.toFile());
                // 最终文件名
                Path finalFile = dir.resolve(c.tailHash + ".que");
                // rename
                Files.move(
                        tempFile,
                        finalFile,
                        StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING
                );

                return c;
            } catch (Exception inner) {
                System.err.println("WRITE FAILED at tempFile=" + tempFile);
                inner.printStackTrace();
                throw inner; // 必须 rethrow，不然下面 rename 又报错
            }






        } catch (Exception e) {
            throw new RuntimeException("容器写入失败 #" + containerNumber, e);
        }
    }

}
