package qcc.name.store;

import qcc.name.codec.QccCanonicalReader;
import qcc.name.codec.QccCanonicalWriter;
import qcc.name.codec.Sha3;
import qcc.name.frame.FramePacket;
import qcc.name.frame.NameFrame;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * 帧日志 + 签名库。两份 OpLogStore，seq 一一对齐：
 *   {dir}/frames/   帧（约 200 字节/条）—— 权威数据，重放的依据
 *   {dir}/sigs/     bytes(签名 4627 字节，expire 为空) | bytes(公钥，链上没有时才有)
 *                   兼容旧格式：整条记录就是签名本体
 * 分开存放：只想核对状态推进的人只需要帧（一亿条约 20GB），要连签名一起验的再取签名库。
 *
 * 写入顺序：先签名后帧。崩溃发生在两者之间时，签名库会比帧日志多一条，
 * 启动时按帧日志的 maxSeq 截齐（多出的签名对应一条从未落盘的帧，丢掉是对的）。
 */
public final class FrameStore implements AutoCloseable {

    private final Path dir;
    private OpLogStore frames;
    private OpLogStore sigs;

    public FrameStore(Path dir) {
        this.dir = dir;
        open();
    }

    private void open() {
        this.frames = new OpLogStore(dir.resolve("frames"));
        this.sigs   = new OpLogStore(dir.resolve("sigs"));
        if (sigs.maxSeq() < frames.maxSeq())
            throw new IllegalStateException("[FrameStore] 签名库落后于帧日志（" + sigs.maxSeq() + " < "
                    + frames.maxSeq() + "）—— 签名缺失，拒绝启动");
        if (sigs.maxSeq() > frames.maxSeq()) {
            // 崩溃残留：签名已写、帧未写。v1 直接重建签名库到帧日志的长度。
            long keep = frames.maxSeq();
            List<byte[]> kept = new ArrayList<>();
            for (long s = 1; s <= keep; s++) kept.add(sigs.read(s));
            sigs.close();
            deleteTree(dir.resolve("sigs"));
            sigs = new OpLogStore(dir.resolve("sigs"));
            for (byte[] b : kept) sigs.append(b);
        }
    }

    public synchronized void append(FramePacket p) {
        long expect = frames.maxSeq() + 1;
        if (p.frame().seq != expect)
            throw new IllegalStateException("[FrameStore] seq 不连续：期望 " + expect + " 实际 " + p.frame().seq);
        byte[] sig = p.signature();
        boolean empty = sig.length == 0;
        if (empty != Sha3.equalsConstantTime(p.frame().sigHash, Sha3.zero32())
                || (!empty && !Sha3.equalsConstantTime(Sha3.hash(sig), p.frame().sigHash)))
            throw new IllegalStateException("[FrameStore] 签名与 sigHash 不符 seq=" + expect);
        sigs.append(p.pubkey().length == 0 && sig.length == 0 ? sig
                : new QccCanonicalWriter(sig.length + p.pubkey().length + 16).bytes(sig).bytes(p.pubkey()).toBytes());
        frames.append(p.frame().encode());
        frames.sync();
        sigs.sync();
    }

    public synchronized long maxSeq() { return frames.maxSeq(); }

    public synchronized NameFrame frame(long seq) {
        byte[] b = frames.read(seq);
        return b == null ? null : NameFrame.decode(b);
    }

    public synchronized FramePacket packet(long seq) {
        NameFrame f = frame(seq);
        if (f == null) return null;
        byte[] rec = sigs.read(seq);
        if (rec.length == 0) return new FramePacket(f, rec);
        try {
            QccCanonicalReader r = new QccCanonicalReader(rec);
            byte[] sig = r.bytes(), pk = r.bytes();
            r.finish();
            return new FramePacket(f, sig, pk);
        } catch (RuntimeException e) {
            return new FramePacket(f, rec);                  // 旧格式：记录即签名
        }
    }

    /** [fromSeq, fromSeq+max) 的帧包，用于同步拉取。 */
    public synchronized List<FramePacket> range(long fromSeq, int max) {
        List<FramePacket> out = new ArrayList<>();
        for (long s = Math.max(1, fromSeq); s <= maxSeq() && out.size() < max; s++) out.add(packet(s));
        return out;
    }

    @Override
    public synchronized void close() {
        frames.close();
        sigs.close();
    }

    /** 清空本节点数据（旧主恢复：清空后全量重新同步）。 */
    public synchronized void wipe() {
        close();
        deleteTree(dir.resolve("frames"));
        deleteTree(dir.resolve("sigs"));
        open();
    }

    public static void deleteTree(Path p) {
        if (!Files.exists(p)) return;
        try (Stream<Path> s = Files.walk(p)) {
            for (Path x : s.sorted(Comparator.reverseOrder()).toList()) Files.delete(x);
        } catch (IOException e) {
            throw new IllegalStateException("删除失败: " + p, e);
        }
    }
}
