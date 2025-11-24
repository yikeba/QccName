package org.example.core.container;

import org.example.core.TimestampUtil;

import java.io.*;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * 容器写入控制器
 * 负责：头部占位 → 区块追加 → 索引写入 → Footer 写入 → 回写头部 → 关闭
 */
public class ContainerWriterController implements Closeable {

    private RandomAccessFile raf;
    private final ContainerHead head;
    private final List<ContainerIndexEntry> indexList = new ArrayList<>();

    // 防止重复 close
    private volatile boolean finished = false;
    private final String filePath;

    public ContainerWriterController(String filePath, long baseTime) {
        this.filePath = filePath;

        this.head = new ContainerHead();
        this.head.baseTime = baseTime;
        this.head.createTime = TimestampUtil.encode(System.currentTimeMillis());

        try {
            this.raf = new RandomAccessFile(filePath, "rw");

            // 写入头部占位
            raf.write(new byte[ContainerHead.FIXED_SIZE]);

        } catch (Exception e) {
            logError("初始化 ContainerWriterController 失败: ", e);
            throw new RuntimeException(e);
        }
    }

    // ------------------ 追加区块 ------------------

    public synchronized void appendBlock(byte[] blockBytes, int height, byte[] blockHash) {
        try {
            long offset = raf.getFilePointer();

            raf.writeInt(blockBytes.length);
            raf.write(blockBytes);

            ContainerIndexEntry entry = new ContainerIndexEntry();
            entry.height = height;
            entry.offset = offset;
            entry.length = blockBytes.length;
            entry.blockHash = blockHash;

            indexList.add(entry);

        } catch (Exception e) {
            logError("写入区块失败: ", e);
            throw new RuntimeException(e);
        }
    }

    // ------------------ 完成写入 ------------------

    public synchronized void finishWrite() {
        if (finished) return;
        finished = true;

        try {

            // 1. 写 Index
            long indexOffset = raf.getFilePointer();
            for (ContainerIndexEntry e : indexList) {
                writeIndexEntry(raf, e);
            }
            long indexLength = raf.getFilePointer() - indexOffset;

            // 2. 写 Footer
            raf.writeLong(indexOffset);
            raf.writeLong(indexLength);

            // 3. 计算整个容器的 Hash
            byte[] containerHash = computeContainerHash();

            // 4. 回写 Head
            head.indexOffset = indexOffset;
            head.indexLength = indexLength;
            head.blockCount = indexList.size();
            head.containerHash = containerHash;

            raf.seek(0);
            writeHead(raf, head);

        } catch (Exception e) {
            logError("finishWrite 失败: ", e);
            throw new RuntimeException(e);

        } finally {
            closeQuietly();
        }
    }

    // ------------------ Closeable ------------------

    @Override
    public void close() {
        finishWrite();
    }

    private void closeQuietly() {
        try {
            if (raf != null) raf.close();
        } catch (Exception ignore) {}
        raf = null;
    }

    // ------------------ 写入工具方法 ------------------

    private void writeIndexEntry(RandomAccessFile raf, ContainerIndexEntry e) throws IOException {
        raf.writeInt(e.height);
        raf.writeLong(e.offset);
        raf.writeInt(e.length);

        raf.writeInt(e.blockHash.length);
        raf.write(e.blockHash);
    }

    private void writeHead(RandomAccessFile raf, ContainerHead h) throws IOException {

        raf.writeLong(h.baseTime);
        raf.writeInt(h.blockCount);
        raf.writeLong(h.indexOffset);
        raf.writeLong(h.indexLength);

        byte[] hash = h.containerHash == null ? new byte[32] : h.containerHash;
        raf.writeInt(hash.length);
        raf.write(hash);

        // createTime (base32 字符串)
        byte[] ct = h.createTime.getBytes();
        raf.writeInt(ct.length);
        raf.write(ct);
    }

    // ------------------ 计算容器哈希 ------------------

    private byte[] computeContainerHash() {
        try (InputStream in = new FileInputStream(filePath)) {

            MessageDigest sha = MessageDigest.getInstance("SHA-256");

            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                sha.update(buf, 0, n);
            }

            return sha.digest();

        } catch (Exception e) {
            logError("计算容器哈希失败: ", e);
            throw new RuntimeException(e);
        }
    }

    // ------------------ 日志 ------------------

    private void logError(String msg, Exception e) {
        System.err.println(msg + e.getMessage());
        e.printStackTrace(System.err);
    }
}

