package qcc.name.store;

import qcc.name.codec.Sha3;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.zip.CRC32;

/**
 * OpLogStore —— 有序、只追加的操作日志。namespace 的唯一权威数据。
 *
 * ═══ 为什么日志是权威、状态是派生的 ═══════════════════════════════
 * 十万级注册 × 约 200 字节 ≈ 20MB。启动时全量重放不到一秒。于是:
 *   - 不需要状态落盘,不需要 last-write-wins 索引,不需要 tombstone 压缩和 GC
 *   - 崩溃恢复 = 重放,不存在"状态与日志不一致"这一整类问题
 *   - 日志本身就是验证者要拉的东西,/v1/log 与节点同步是同一套代码
 * 亿级时再加状态快照,现在不做。
 *
 * ═══ 与 SignatureVault 的关系 ═════════════════════════════════════
 * 段式布局、128MB 封口、流式索引重建、按段同步全部沿用。五处必须改:
 *
 *   1. 【持久性】SignatureVault 用 Files.write(APPEND),不 force。
 *      断电丢最后几条。签名缓存丢了能重拉,namespace 注册丢了就是
 *      用户账户凭空消失。这里改成常驻 FileChannel + sync() 显式 force,
 *      由 EpochBuilder 在 epoch 封口时调用。
 *
 *   2. 【性能】原实现每写一条 open/close 一次文件。这里常驻 channel。
 *
 *   3. 【正确性】原实现的写入 offset 取自内存里的 currentSegSize,
 *      崩溃重启后可能与文件实际大小不符,索引 offset 就全错了。
 *      这里一律取 channel.size()。
 *   4. 【严格性】长度、魔数、CRC 全部校验,不静默跳过。
 *   5. 【完整性】检测段间隙。原实现 seg_0 与 seg_2 存在、seg_1 缺失时
 *      静默跳过 —— 同步中断就是这个形态,意味着一段历史消失而节点照常启动。
 * 另外新增两项 SignatureVault 没有的:
 *   - 尾部残记录恢复:崩溃可能留下写了一半的记录,启动时截断掉
 *   - CRC32:廉价地区分"写了一半"和"内容被改过"
 * ═══ 磁盘格式 ═════════════════════════════════════════════════════
 *   文件名  oplog_{segIndex}.qlog
 *   段头    [SEG_MAGIC 4]["QNLG"][version 4][segIndex 4][reserved 4]  = 16 字节
 *   记录    [REC_MAGIC 4][seq 8][len 4][payload len 字节][crc32 4]
 *           crc32 覆盖 seq + len + payload
 * seq 从 1 开始,连续无空洞。
 * 线程安全:写入串行化(单线程推动状态,写也只有一个线程);读可并发。
 */
public final class OpLogStore implements AutoCloseable {

    private static final int  SEG_MAGIC       = 0x514E4C47; // 'QNLG'
    private static final int  REC_MAGIC       = 0x514E4F50; // 'QNOP'
    private static final int  FORMAT_VERSION  = 1;
    private static final int  SEG_HEADER_LEN  = 16;
    private static final int  REC_OVERHEAD    = 4 + 8 + 4 + 4;   // magic+seq+len+crc
    private static final long SEG_MAX_BYTES   = 128L * 1024 * 1024;
    private static final int  MAX_RECORD_LEN  = 1024 * 1024;     // 单条操作上限 1MB

    private final Path dir;
    private final Object writeLock = new Object();

    /**
     * 索引:数组下标 = seq-1,值打包 (segIndex 16位 | offset 28位 | recLen 20位)。
     * seq 连续,所以用数组而不是 Map —— 8 字节/条,十万级 800KB。
     */
    private long[] index = new long[1024];
    private long   maxSeq;          // 已写入的最大 seq;0 表示空

    private int         curSeg;
    private FileChannel curChannel;

    // ── 生命周期 ──────────────────────────────────────────────────

    public OpLogStore(Path dir) {
        this.dir = dir;
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            throw new IllegalStateException("[OpLogStore] 目录创建失败: " + dir, e);
        }
        rebuild();
    }

    @Override
    public void close() {
        synchronized (writeLock) {
            if (curChannel != null) {
                try { curChannel.force(true); curChannel.close(); }
                catch (IOException ignored) { }
                curChannel = null;
            }
        }
    }

    // ── 启动:扫描全部段,重建索引 ─────────────────────────────────

    private void rebuild() {
        List<Path> segs = listSegments();

        // 段间隙检测:必须是 0,1,2,... 连续。缺一个就是历史缺失,拒绝启动。
        for (int i = 0; i < segs.size(); i++) {
            int idx = segIndexOf(segs.get(i));
            if (idx != i)
                throw new IllegalStateException(
                        "[OpLogStore] 段序号不连续:期望 oplog_" + i + ".qlog,实际 oplog_" + idx
                                + ".qlog。说明有一段日志缺失(同步中断?),拒绝启动 —— "
                                + "带着空洞运行会让重放结果与其他节点不一致。");
        }

        maxSeq = 0;
        for (Path seg : segs) scanSegment(seg);

        curSeg = segs.isEmpty() ? 0 : segs.size() - 1;
        long curSize = segSizeOrHeader(curSeg);
        if (curSize >= SEG_MAX_BYTES) curSeg++;   // 尾段已满,下一条写新段
    }

    /** 扫描一个段,填索引;遇到写了一半的尾记录就截断。 */
    private void scanSegment(Path seg) {
        int segIdx = segIndexOf(seg);
        try (FileChannel ch = FileChannel.open(seg, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            long size = ch.size();
            if (size < SEG_HEADER_LEN)
                throw new IllegalStateException("[OpLogStore] 段头不完整: " + seg);

            ByteBuffer hdr = readAt(ch, 0, SEG_HEADER_LEN);
            if (hdr.getInt() != SEG_MAGIC)
                throw new IllegalStateException("[OpLogStore] 段魔数错误: " + seg);
            int ver = hdr.getInt();
            if (ver != FORMAT_VERSION)
                throw new IllegalStateException("[OpLogStore] 段格式版本 " + ver
                        + " 本实现只认识 " + FORMAT_VERSION + ": " + seg);
            int storedIdx = hdr.getInt();
            if (storedIdx != segIdx)
                throw new IllegalStateException("[OpLogStore] 段头 segIndex=" + storedIdx
                        + " 与文件名 " + seg.getFileName() + " 不符");

            long pos = SEG_HEADER_LEN;
            while (pos + REC_OVERHEAD <= size) {
                ByteBuffer h = readAt(ch, pos, 16);
                if (h.getInt() != REC_MAGIC) {
                    truncate(ch, seg, pos, "记录魔数错误");
                    break;
                }
                long seq = h.getLong();
                int  len = h.getInt();
                if (len < 0 || len > MAX_RECORD_LEN) {
                    truncate(ch, seg, pos, "记录长度非法 " + len);
                    break;
                }
                long recLen = REC_OVERHEAD + (long) len;
                if (pos + recLen > size) {
                    truncate(ch, seg, pos, "记录不完整");
                    break;
                }
                ByteBuffer body = readAt(ch, pos + 16, len + 4);
                byte[] payload = new byte[len];
                body.get(payload);
                int crcStored = body.getInt();
                if (crcStored != crc(seq, payload)) {
                    truncate(ch, seg, pos, "CRC 校验失败,记录已损坏");
                    break;
                }
                if (seq != maxSeq + 1)
                    throw new IllegalStateException("[OpLogStore] seq 不连续:期望 "
                            + (maxSeq + 1) + " 读到 " + seq + " @ " + seg + ":" + pos);

                putIndex(seq, segIdx, pos, (int) recLen);
                maxSeq = seq;
                pos += recLen;
            }
        } catch (IOException e) {
            throw new IllegalStateException("[OpLogStore] 扫描失败: " + seg, e);
        }
    }

    /**
     * 记录解析失败时的处理。**区分两种情况,后果完全不同:**
     *
     *   崩溃残尾 —— 进程在写一半时挂掉,坏记录之后什么都没有。
     *               截断掉继续跑是对的,那条记录本来也没确认给用户。
     *
     *   中间损坏 —— 坏记录之后**还有完整记录**。这不可能是崩溃造成的
     *               (崩溃不会先写坏一条再写好后面几条),只可能是篡改
     *               或磁盘损坏。此时截断等于把后半段历史静默删掉 ——
     *               而那些记录可能已经被 epoch 锚定上链、已经发过收据。
     *               必须拒绝启动。
     */
    private void truncate(FileChannel ch, Path seg, long pos, String why) throws IOException {
        long size = ch.size();
        if (pos >= size) return;
        if (hasValidRecordAfter(ch, pos, size))
            throw new IllegalStateException(
                    "[OpLogStore] " + seg.getFileName() + " 在 offset " + pos + " 处损坏("
                            + why + "),但其后仍有完整记录 —— 这不是崩溃残留,是篡改或磁盘损坏。"
                            + "拒绝启动:截断会静默删除已锚定的历史。");
        System.err.println("[OpLogStore] " + seg.getFileName() + " 在 offset " + pos
                + " 处截断(" + why + ",崩溃残留),丢弃 " + (size - pos) + " 字节");
        ch.truncate(pos);
        ch.force(true);
    }

    /** 从 pos 之后逐字节找下一个完整且 CRC 正确的记录。找到即说明不是残尾。 */
    private boolean hasValidRecordAfter(FileChannel ch, long pos, long size) throws IOException {
        for (long p = pos + 1; p + REC_OVERHEAD <= size; p++) {
            ByteBuffer h = readAt(ch, p, 16);
            if (h.getInt() != REC_MAGIC) continue;
            long seq = h.getLong();
            int  len = h.getInt();
            if (len < 0 || len > MAX_RECORD_LEN) continue;
            if (p + REC_OVERHEAD + (long) len > size) continue;
            ByteBuffer body = readAt(ch, p + 16, len + 4);
            byte[] payload = new byte[len];
            body.get(payload);
            if (body.getInt() == crc(seq, payload)) return true;
        }
        return false;
    }

    // ── 写入 ──────────────────────────────────────────────────────

    /**
     * 追加一条操作。返回分配到的 seq(从 1 开始)。
     * 不做 force —— 由 EpochBuilder 在 epoch 封口时调用 sync() 统一刷盘。
     * 单条 force 的代价在注册高峰下不可接受,而 epoch 是天然的持久化边界:
     * 未 force 的记录也还没被锚定上链,重放丢掉它们不会造成对外不一致。
     */
    public long append(byte[] payload) {
        if (payload == null) throw new IllegalArgumentException("payload is null");
        if (payload.length > MAX_RECORD_LEN)
            throw new IllegalArgumentException("单条操作超过 " + MAX_RECORD_LEN + " 字节: " + payload.length);

        synchronized (writeLock) {
            long seq = maxSeq + 1;
            try {
                FileChannel ch = channelFor(curSeg);
                long offset = ch.size();                  // 取实际大小,不用内存跟踪值

                int recLen = REC_OVERHEAD + payload.length;
                ByteBuffer rec = ByteBuffer.allocate(recLen);
                rec.putInt(REC_MAGIC);
                rec.putLong(seq);
                rec.putInt(payload.length);
                rec.put(payload);
                rec.putInt(crc(seq, payload));
                rec.flip();
                // 显式定位写入,不用 APPEND 模式:APPEND 与 READ 在 Unix 上互斥,
                // 而且我们本来就需要 ch.size() 作为 offset(见上),两者一致更不易出错。
                long wp = offset;
                while (rec.hasRemaining()) wp += ch.write(rec, wp);

                putIndex(seq, curSeg, offset, recLen);
                maxSeq = seq;

                if (offset + recLen >= SEG_MAX_BYTES) {   // 封口,下一条开新段
                    ch.force(true);
                    ch.close();
                    curChannel = null;
                    curSeg++;
                }
                return seq;
            } catch (IOException e) {
                throw new IllegalStateException("[OpLogStore] 追加失败 seq=" + seq, e);
            }
        }
    }

    /** 强制刷盘。epoch 封口时必须调用,否则断电会丢已确认的注册。 */
    public void sync() {
        synchronized (writeLock) {
            if (curChannel != null) {
                try { curChannel.force(false); }
                catch (IOException e) { throw new IllegalStateException("[OpLogStore] force 失败", e); }
            }
        }
    }

    // ── 读取 ──────────────────────────────────────────────────────

    public long maxSeq() { return maxSeq; }

    public boolean isEmpty() { return maxSeq == 0; }

    /** 按 seq 读一条 payload。不存在返回 null。 */
    public byte[] read(long seq) {
        if (seq < 1 || seq > maxSeq) return null;
        long packed = index[(int) (seq - 1)];
        int segIdx = (int) (packed >>> 48);
        long offset = (packed >>> 20) & 0x0FFFFFFFL;
        int recLen  = (int) (packed & 0xFFFFF);
        try (FileChannel ch = FileChannel.open(segPath(segIdx), StandardOpenOption.READ)) {
            ByteBuffer b = readAt(ch, offset, recLen);
            if (b.getInt() != REC_MAGIC) throw new IllegalStateException("记录魔数错误 seq=" + seq);
            long s = b.getLong();
            if (s != seq) throw new IllegalStateException("seq 不符:期望 " + seq + " 读到 " + s);
            int len = b.getInt();
            byte[] payload = new byte[len];
            b.get(payload);
            if (b.getInt() != crc(seq, payload)) throw new IllegalStateException("CRC 失败 seq=" + seq);
            return payload;
        } catch (IOException e) {
            throw new IllegalStateException("[OpLogStore] 读取失败 seq=" + seq, e);
        }
    }

    /** 顺序消费 [fromSeq, toSeq]。重放器和 /v1/log 都走这里。 */
    public void forEach(long fromSeq, long toSeq, java.util.function.BiConsumer<Long, byte[]> fn) {
        long lo = Math.max(1, fromSeq);
        long hi = Math.min(maxSeq, toSeq);
        for (long s = lo; s <= hi; s++) fn.accept(s, read(s));
    }

    // ── 段级同步(与 SignatureVaultApi 的三个接口一一对应)───────────

    public int segmentCount() { return listSegments().size(); }

    public long segmentSize(int segIndex) {
        Path p = segPath(segIndex);
        try { return Files.exists(p) ? Files.size(p) : -1L; }
        catch (IOException e) { return -1L; }
    }

    /** 零拷贝写出整段。对应 GET /v1/log/file/{segIndex}。 */
    public boolean exportSegment(int segIndex, OutputStream out) throws IOException {
        Path seg = segPath(segIndex);
        if (!Files.exists(seg)) return false;
        try (FileChannel fc = FileChannel.open(seg, StandardOpenOption.READ)) {
            WritableByteChannel wc = Channels.newChannel(out);
            long size = fc.size(), pos = 0;
            while (pos < size) pos += fc.transferTo(pos, size - pos, wc);
        }
        out.flush();
        return true;
    }

    // ── 内部 ──────────────────────────────────────────────────────

    private FileChannel channelFor(int segIdx) throws IOException {
        if (curChannel != null && segIdx == curSeg) return curChannel;
        if (curChannel != null) { curChannel.force(true); curChannel.close(); }
        Path p = segPath(segIdx);
        boolean fresh = !Files.exists(p);
        curChannel = FileChannel.open(p,
                StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);
        if (fresh) {
            ByteBuffer hdr = ByteBuffer.allocate(SEG_HEADER_LEN);
            hdr.putInt(SEG_MAGIC).putInt(FORMAT_VERSION).putInt(segIdx).putInt(0);
            hdr.flip();
            long hp = 0;
            while (hdr.hasRemaining()) hp += curChannel.write(hdr, hp);
            curChannel.force(true);   // 段头必须落盘,否则崩溃后是个无头文件
        }
        return curChannel;
    }

    private void putIndex(long seq, int segIdx, long offset, int recLen) {
        if (segIdx > 0xFFFF)      throw new IllegalStateException("段序号超过 65535: " + segIdx);
        if (offset > 0x0FFFFFFFL) throw new IllegalStateException("段内偏移超过 256MB: " + offset);
        if (recLen > 0xFFFFF)     throw new IllegalStateException("记录超过 1MB: " + recLen);
        int i = (int) (seq - 1);
        if (i >= index.length) {
            long[] bigger = new long[Math.max(index.length * 2, i + 1)];
            System.arraycopy(index, 0, bigger, 0, index.length);
            index = bigger;
        }
        index[i] = ((long) segIdx << 48) | (offset << 20) | recLen;
    }

    private static int crc(long seq, byte[] payload) {
        CRC32 c = new CRC32();
        for (int i = 56; i >= 0; i -= 8) c.update((int) (seq >>> i) & 0xFF);
        c.update(payload, 0, payload.length);
        return (int) c.getValue();
    }

    private static ByteBuffer readAt(FileChannel ch, long pos, int len) throws IOException {
        ByteBuffer b = ByteBuffer.allocate(len);
        int read = 0;
        while (read < len) {
            int n = ch.read(b, pos + read);
            if (n < 0) throw new IOException("提前 EOF @ " + (pos + read));
            read += n;
        }
        b.flip();
        return b;
    }

    private long segSizeOrHeader(int segIdx) {
        long s = segmentSize(segIdx);
        return s < 0 ? SEG_HEADER_LEN : s;
    }

    private Path segPath(int segIndex) { return dir.resolve("oplog_" + segIndex + ".qlog"); }

    private List<Path> listSegments() {
        List<Path> out = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, "oplog_*.qlog")) {
            for (Path p : ds) out.add(p);
        } catch (IOException e) {
            throw new IllegalStateException("[OpLogStore] 列目录失败: " + dir, e);
        }
        out.sort(Comparator.comparingInt(OpLogStore::segIndexOf));
        return out;
    }

    private static int segIndexOf(Path p) {
        String n = p.getFileName().toString();
        try {
            return Integer.parseInt(n.substring("oplog_".length(), n.length() - ".qlog".length()));
        } catch (Exception e) {
            throw new IllegalStateException("[OpLogStore] 无法解析段序号: " + n);
        }
    }

    /** 整条日志的摘要,用于快速比对两个节点是否同步到同一位置。 */
    public String digest() {
        return "{\"maxSeq\":" + maxSeq + ",\"segments\":" + segmentCount() + "}";
    }

    /** 日志内容哈希 —— 顺序哈希链,证明日志未被重排或插入。 */
    public byte[] seqHash(long fromSeq, long toSeq) {
        byte[] acc = Sha3.zero32();
        for (long s = Math.max(1, fromSeq); s <= Math.min(maxSeq, toSeq); s++) {
            acc = Sha3.hash(acc, read(s));
        }
        return acc;
    }
}