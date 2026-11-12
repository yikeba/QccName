package qcc.name.store;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 公钥快照（参照 QCC AddressKeyVault 的思路简化）：只保存链上没有公钥的地址（0 资产签名钱包）。
 *
 *   文件 {dir}/pubkeys.qpk，只追加：
 *     [ MAGIC "QPKV" 4B ][ addrLen 2B ][ addr ][ pkLen 2B ][ pk 原始字节 ][ seq 8B ]
 *   内存：address → 文件偏移（每条约 100 字节），公钥按需从磁盘读，热点放 LRU（上限 4096 条）。
 *
 * 写入前调用方必须已确认 QccAddress.matches(pk, address)：公钥由地址推导关系绑定，
 * 存在本库里的每一条都是"正确"的，多存一条也不会错 —— 所以清空帧日志重新同步时不需要清空本库。
 */
public final class PubkeyVault implements AutoCloseable {

    private static final int MAGIC = 0x51504B56;   // "QPKV"
    private static final int MAX_HOT = 4096;

    private final Path file;
    private final Map<String, Long> index = new ConcurrentHashMap<>();
    private final Map<String, byte[]> hot = Collections.synchronizedMap(new LinkedHashMap<>(256, 0.75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<String, byte[]> e) { return size() > MAX_HOT; }
    });
    private RandomAccessFile raf;

    public PubkeyVault(Path dir) {
        try {
            Files.createDirectories(dir);
            this.file = dir.resolve("pubkeys.qpk");
            this.raf = new RandomAccessFile(file.toFile(), "rw");
            rebuild();
        } catch (IOException e) {
            throw new IllegalStateException("[PubkeyVault] 打开失败: " + e.getMessage(), e);
        }
    }

    /** 启动扫描建立索引；末尾不完整的记录（写入中断）截掉。 */
    private void rebuild() throws IOException {
        long pos = 0, len = raf.length();
        while (pos + 8 <= len) {
            raf.seek(pos);
            if (raf.readInt() != MAGIC) break;
            int al = raf.readUnsignedShort();
            if (pos + 6 + al + 2 > len) break;
            byte[] a = new byte[al];
            raf.readFully(a);
            int pl = raf.readUnsignedShort();
            long end = pos + 6 + al + 2 + pl + 8;
            if (end > len) break;
            index.putIfAbsent(new String(a, StandardCharsets.UTF_8), pos);
            pos = end;
        }
        if (pos < len) {
            System.err.println("[PubkeyVault] 截掉末尾不完整记录 " + (len - pos) + " 字节");
            raf.setLength(pos);
        }
    }

    public boolean contains(String address) { return index.containsKey(address); }

    public int size() { return index.size(); }

    /** 取公钥；没有返回 null。 */
    public synchronized byte[] get(String address) {
        byte[] h = hot.get(address);
        if (h != null) return h;
        Long off = index.get(address);
        if (off == null) return null;
        try {
            raf.seek(off);
            raf.readInt();
            raf.skipBytes(raf.readUnsignedShort());
            byte[] pk = new byte[raf.readUnsignedShort()];
            raf.readFully(pk);
            hot.put(address, pk);
            return pk;
        } catch (IOException e) {
            System.err.println("[PubkeyVault] 读取失败 " + address + ": " + e.getMessage());
            return null;
        }
    }

    /** 写入（幂等：已存在则忽略）。返回是否新写入。 */
    public synchronized boolean put(String address, byte[] pubkey, long seq) {
        if (index.containsKey(address)) return false;
        byte[] a = address.getBytes(StandardCharsets.UTF_8);
        ByteBuffer b = ByteBuffer.allocate(4 + 2 + a.length + 2 + pubkey.length + 8);
        b.putInt(MAGIC).putShort((short) a.length).put(a).putShort((short) pubkey.length).put(pubkey).putLong(seq);
        try {
            long off = raf.length();
            raf.seek(off);
            raf.write(b.array());
            raf.getFD().sync();
            index.put(address, off);
            hot.put(address, pubkey.clone());
            return true;
        } catch (IOException e) {
            throw new IllegalStateException("[PubkeyVault] 写入失败: " + e.getMessage(), e);
        }
    }

    @Override
    public synchronized void close() {
        try { raf.close(); } catch (IOException ignored) { }
    }
}
