// Container.java —— 纯粹的硬盘存储器（全球最硬冷数据版）
package org.example.core;

import org.bouncycastle.util.encoders.Hex;
import org.example.config.QubePath;

import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class Container {

    private static final AtomicLong ID_GENERATOR = new AtomicLong(System.currentTimeMillis() / 1000);

    public final long containerId;                                 // 只读ID
    public final Path containerFile;                               // 文件路径
    private final RandomAccessFile writer;                         // 裸文件流
    private final AtomicLong offset = new AtomicLong(0);

    // 内存索引（方便快速查询，不参与共识）
    public final ConcurrentHashMap<String, BlockIndex> indexMap = new ConcurrentHashMap<>();

    // ==================== 构造：只负责创建文件，不干任何事 ====================
    public Container() {
        this.containerId = ID_GENERATOR.incrementAndGet();

        try {
            Files.createDirectories(QubePath.CONTAINER_DIR);
            this.containerFile = QubePath.CONTAINER_DIR.resolve("container_" + containerId + ".qube");
            this.writer = new RandomAccessFile(containerFile.toFile(), "rw");

            System.out.println("容器文件已创建 → " + containerFile.toAbsolutePath());
            System.out.println("ID = " + containerId + "，等待区块写入...");

        } catch (Exception e) {
            throw new RuntimeException("容器文件创建失败，节点无法运行", e);
        }
    }

    // ==================== 核心：写入一个密封好的区块（Manager 决定何时调用） ====================
    public synchronized void appendBlock(Block sealedBlock) {
        try {
            byte[] blockData = sealedBlock.serialize();
            long currentOffset = offset.get();

            writer.seek(currentOffset);
            writer.writeInt(blockData.length);   // 长度前缀
            writer.write(blockData);              // 区块本体
            offset.addAndGet(4 + blockData.length);

            // 建立内存索引
            BlockIndex idx = new BlockIndex();
            idx.height = sealedBlock.height;
            idx.offset = currentOffset;
            idx.length = 4 + blockData.length;
            idx.blockHash = sealedBlock.blockHash;
            idx.timestamp = sealedBlock.timestamp;
            indexMap.put(Hex.toHexString(sealedBlock.blockHash), idx);

            System.out.println("区块 height=" + sealedBlock.height +
                    " 已写入容器 " + containerId +
                    "，偏移=" + currentOffset +
                    "，大小=" + blockData.length + " bytes");

        } catch (Exception e) {
            throw new RuntimeException("写入区块到容器失败", e);
        }
    }

    // ==================== 密封：关闭文件流，变为冷数据 ====================
    public synchronized void sealAndClose() {
        try {
            if (writer != null) {
                writer.close();
            }
            System.out.println("容器 " + containerId + " 已密封并关闭，成为冷数据文件");
            System.out.println("最终大小: " + containerFile.toFile().length() + " bytes");
            System.out.println("共包含区块数: " + indexMap.size());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ==================== 归档：移动到历史目录 ====================
    public void archive() {
        try {
            Path archived = QubePath.DATA_DIR.resolve(containerFile.getFileName());
            Files.move(containerFile, archived);
            System.out.println("容器已归档 → " + archived);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ==================== 只读信息 ====================
    public long getFileSize() { return containerFile.toFile().length(); }
    public Path getFilePath() { return containerFile; }
    public int getBlockCount() { return indexMap.size(); }

    public static class BlockIndex {
        public short height;
        public long offset;
        public int length;
        public byte[] blockHash;
        public long timestamp;
    }
}