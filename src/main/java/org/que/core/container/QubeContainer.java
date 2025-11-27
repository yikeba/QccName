package org.que.core.container;

import org.que.config.QubePath;
import org.que.core.block.QubeBlock;
import org.que.crypto.CryptoUtil;
import org.que.util.TimestampUtil;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * QubeContainer —— 无 Footer 版本（尾部固定 32 字节哈希）
 *
 * 文件布局：
 * [0..255]               : ContainerHead
 * [Blocks...]            : 每条区块：[int length][bytes]
 * [IndexEntries...]      : 定长索引结构（每条 48 bytes）
 * [Hash(32)]             : 容器最终哈希（排除这 32 字节）
 */
public final class QubeContainer implements Closeable {

    public static final long DEFAULT_MAX_SIZE_BYTES = 200L * 1024 * 1024;
    public static final long DEFAULT_MAX_LIFETIME_MS = 3L * 60 * 1000;

    public final Path path;
    private final RandomAccessFile raf;
    private final ContainerHead head;

    private final List<ContainerIndexEntry> indexList;

    private final long createTimeMillis;
    private long lastAppendTimeMillis;
    private boolean sealed;
    private final long maxSizeBytes;

    // ========== 1. 创建新容器 ==========
    public static QubeContainer createNewForContract(byte[] contractAddress) throws IOException {
        Files.createDirectories(QubePath.CONTAINER_DIR);

        long now = System.currentTimeMillis();
        long nano = System.nanoTime();

        String prefix = bytesToHex(contractAddress);
        if (prefix.length() > 16) prefix = prefix.substring(0, 16);

        String fileName = String.format(
                "container_%s_%d_%08x.qbc",
                prefix, now, (int)(nano & 0xFFFFFFFFL)
        );

        Path fullPath = QubePath.CONTAINER_DIR.resolve(fileName);
        return new QubeContainer(fullPath, now, DEFAULT_MAX_SIZE_BYTES);
    }

    private QubeContainer(Path path, long baseTime, long maxSizeBytes) throws IOException {
        this.path = path;
        this.maxSizeBytes = maxSizeBytes;
        this.createTimeMillis = baseTime;
        this.lastAppendTimeMillis = baseTime;
        this.sealed = false;
        this.indexList = new ArrayList<>();

        this.raf = new RandomAccessFile(path.toFile(), "rw");

        // 初始化 head
        this.head = new ContainerHead();
        this.head.magic = "QUBE";
        this.head.version = 1;
        this.head.baseTime = baseTime;
        this.head.blockCount = 0;
        this.head.indexOffset = 0;
        this.head.indexLength = 0;
        this.head.containerHash = new byte[32];
        this.head.createTime = TimestampUtil.encode(System.currentTimeMillis());

        // 占位写 head
        raf.seek(0);
        raf.write(new byte[ContainerHead.FIXED_SIZE]);
    }

    // ========== 2. 打开已有容器（读取 + 校验） ==========
    /** 只读打开已封存容器（生产/验证用） */
    public static QubeContainer openExisting(Path path) throws IOException {
        RandomAccessFile raf = new RandomAccessFile(path.toFile(), "r");
        ContainerHead head = readHead(raf);

        // 读取最后 32 字节作为真实 hash
        long fileLen = raf.length();
        if (fileLen < 256 + 32) throw new IOException("容器文件太短");

        raf.seek(fileLen - 32);
        byte[] tailHash = new byte[32];
        raf.readFully(tailHash);
        head.containerHash = tailHash;  // 覆盖 head 里的（防止 head 被篡改）

        List<ContainerIndexEntry> indexList = readIndex(raf, head.indexOffset, head.indexLength);

        QubeContainer c = new QubeContainer(path, raf, head, indexList, true);
        return c;
    }

    /** 私有构造器：用于 openExisting */
    private QubeContainer(Path path, RandomAccessFile raf, ContainerHead head,
                          List<ContainerIndexEntry> indexList, boolean sealed) {
        this.path = path;
        this.raf = raf;
        this.head = head;
        this.indexList = new ArrayList<>(indexList);
        this.createTimeMillis = head.baseTime;
        this.lastAppendTimeMillis = createTimeMillis;
        this.sealed = sealed;
        this.maxSizeBytes = DEFAULT_MAX_SIZE_BYTES;
    }
    // ========== 3. 追加区块 ==========
    public synchronized void appendBlock(QubeBlock block, byte[] blockBytes) {
        if (sealed)
            throw new IllegalStateException("容器已封存");

        try {
            long currentSize = raf.length();
            if (currentSize >= maxSizeBytes)
                throw new IllegalStateException("达到容量上限");

            raf.seek(currentSize);
            long offset = raf.getFilePointer();

            raf.writeInt(blockBytes.length);
            raf.write(blockBytes);

            ContainerIndexEntry e = new ContainerIndexEntry(
                    block.getBlockNumber(),
                    offset,
                    blockBytes.length,
                    CryptoUtil.sha3256(blockBytes)
            );
            indexList.add(e);

            lastAppendTimeMillis = System.currentTimeMillis();

        } catch (IOException ex) {
            throw new RuntimeException("appendBlock 写入失败", ex);
        }
    }

    // ========== 4. 封存容器（写索引 + 写尾部32字节 hash） ==========
    /** 封存容器：写入索引 + 计算最终哈希 + 回写最后 32 字节 + 回写 head */
    public synchronized void seal() throws IOException {
        if (sealed) return;
        // 1. 写入索引区
        long indexStart = raf.getFilePointer();
        for (ContainerIndexEntry e : indexList) {
            writeIndexEntry(raf, e);
        }
        long indexEnd = raf.getFilePointer();
        // 2. 预留最后 32 字节（先写 0）
        raf.write(new byte[32]);
        // 3. 计算【从 0 到 length-32】的哈希（不包含最后 32 字节）
        byte[] finalHash = computeHashExcludeTail();
        // 4. 回写真正的 hash 到最后 32 字节
        raf.seek(raf.length() - 32);
        raf.write(finalHash);
        // 5. 更新并回写 head
        head.blockCount = indexList.size();
        head.indexOffset = indexStart;
        head.indexLength = indexEnd - indexStart;
        head.containerHash = finalHash.clone();
        head.setSealedAt(System.currentTimeMillis());
        raf.seek(0);
        writeHead(raf, head);
        sealed = true;
        System.out.println("容器封存成功: " + path.getFileName());
        System.out.println("    └─ 最终哈希: " + bytesToHex(finalHash));
    }

    // ========== 5. 读取区块 ==========
    public synchronized byte[] readBlockBytes(int height) throws IOException {
        for (ContainerIndexEntry e : indexList) {
            if (e.getHeight() == height) {
                byte[] data = new byte[e.getLength()];
                raf.seek(e.getOffset() + 4);
                raf.readFully(data);
                return data;
            }
        }
        return null;
    }

    // ========== 6. 验证容器 ==========
    public boolean verifyContainer() {
        try {
            byte[] calc = computeHashExcludeTail();
            return Arrays.equals(calc, head.containerHash);
        } catch (Exception e) {
            return false;
        }
    }

    private byte[] computeHashExcludeTail() throws IOException {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        long end = raf.length() - 32;
        if (end <= 0) throw new IOException("文件太短");
        raf.seek(0);
        byte[] buf = new byte[1024 * 1024];
        long remaining = end;
        while (remaining > 0) {
            int toRead = (int) Math.min(buf.length, remaining);
            int read = raf.read(buf, 0, toRead);
            if (read == -1) break;
            md.update(buf, 0, read);
            remaining -= read;
        }

        return md.digest();
    }

    // ========== 写 / 读 Head 和 Index ==========
    private static void writeHead(RandomAccessFile raf, ContainerHead h) throws IOException {
        raf.write(h.magic.getBytes(StandardCharsets.UTF_8));
        raf.writeShort(h.version);
        raf.write(h.containerHash);
        raf.writeLong(h.baseTime);
        raf.writeInt(h.blockCount);
        raf.writeLong(h.indexOffset);
        raf.writeLong(h.indexLength);
        raf.write(h.reserved);
    }

    private static ContainerHead readHead(RandomAccessFile raf) throws IOException {
        raf.seek(0);
        ContainerHead h = new ContainerHead();

        byte[] magic = new byte[4];
        raf.readFully(magic);
        h.magic = new String(magic, StandardCharsets.UTF_8);

        h.version = raf.readShort();

        byte[] hash = new byte[32];
        raf.readFully(hash);
        h.containerHash = hash;

        h.baseTime = raf.readLong();
        h.blockCount = raf.readInt();
        h.indexOffset = raf.readLong();
        h.indexLength = raf.readLong();

        byte[] res = new byte[ContainerHead.FIXED_SIZE - 4 - 2 - 32 - 8 - 4 - 8 - 8];
        raf.readFully(res);
        h.reserved = res;

        return h;
    }

    private static void writeIndexEntry(RandomAccessFile raf, ContainerIndexEntry e) throws IOException {
        raf.writeInt(e.getHeight());
        raf.writeLong(e.getOffset());
        raf.writeInt(e.getLength());

        byte[] bh = e.getBlockHash();
        if (bh.length != 32) throw new IOException("blockHash 必须 32 字节");
        raf.write(bh);
    }

    private static List<ContainerIndexEntry> readIndex(RandomAccessFile raf, long offset, long length) throws IOException {
        List<ContainerIndexEntry> list = new ArrayList<>();
        if (offset <= 0 || length <= 0) return list;

        raf.seek(offset);
        long end = offset + length;

        while (raf.getFilePointer() < end) {
            int height = raf.readInt();
            long off = raf.readLong();
            int len = raf.readInt();

            byte[] hash = new byte[32];
            raf.readFully(hash);

            list.add(new ContainerIndexEntry(height, off, len, hash));
        }
        return list;
    }

    // ========== 工具 ==========
    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    @Override
    public void close() throws IOException {
        raf.close();
    }
}
