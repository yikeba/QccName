package qcc;

import qcc.util.Sha3;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * qcc-canonical-binary/1 —— 规范二进制读取器。
 *
 * 与 QccBaseData.read* 系列的关键差异:**全部越界都抛异常,没有一处静默容错。**
 *
 * QccBaseData.readString 里 `if (len <= 0) return ""` 有两个问题:
 *   - 负长度不消耗字节,后续所有字段读取错位,却不报错
 *   - 一个构造出来的 len = 0x40000000 会直接 new byte[1GB],
 *     一条恶意记录就能 OOM 掉节点
 * 这些数据来自网络和磁盘,两者都可能被污染,所以读取器必须是防御性的。
 *
 * finish() 强制要求字节被完全消费:尾部有多余字节说明格式对不上,
 * 静默忽略会让两个不同的输入解析成同一个对象。
 */
public final class QccCanonicalReader {

    private final byte[] a;
    private int pos;
    private final int end;

    public QccCanonicalReader(byte[] data) {
        if (data == null) throw new IllegalArgumentException("data is null");
        this.a = data;
        this.pos = 0;
        this.end = data.length;
    }

    public QccCanonicalReader(byte[] data, int offset, int length) {
        if (data == null) throw new IllegalArgumentException("data is null");
        if (offset < 0 || length < 0 || offset + length > data.length)
            throw new IllegalArgumentException("越界的窗口: off=" + offset + " len=" + length);
        this.a = data;
        this.pos = offset;
        this.end = offset + length;
    }

    public int position()  { return pos; }
    public int remaining() { return end - pos; }

    private void need(int n) {
        if (n < 0 || remaining() < n)
            throw new IllegalStateException(
                    "读取越界: 需要 " + n + " 字节,剩余 " + remaining() + " (pos=" + pos + ")");
    }

    // ── 定长 ──────────────────────────────────────────────────────

    public int u8() {
        need(1);
        return a[pos++] & 0xFF;
    }

    public boolean bool() {
        int v = u8();
        if (v != 0 && v != 1) throw new IllegalStateException("bool 只接受 0/1,读到: " + v);
        return v == 1;
    }

    public long u32() {
        need(4);
        long v = ((long) (a[pos] & 0xFF) << 24)
               | ((a[pos + 1] & 0xFF) << 16)
               | ((a[pos + 2] & 0xFF) << 8)
               |  (a[pos + 3] & 0xFF);
        pos += 4;
        return v;
    }

    public long i64() {
        need(8);
        long v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | (a[pos + i] & 0xFF);
        pos += 8;
        return v;
    }

    /** 与 writer.u64 对称:读到负值说明编码方违反了 intOverflow=reject。 */
    public long u64() {
        long v = i64();
        if (v < 0) throw new IllegalStateException("u64 读到负值: " + v);
        return v;
    }

    public byte[] fixed(int len) {
        need(len);
        byte[] out = new byte[len];
        System.arraycopy(a, pos, out, 0, len);
        pos += len;
        return out;
    }

    public byte[] hash32()    { return fixed(Sha3.HASH_LEN); }

    public String hash32Hex() { return Sha3.toHex(hash32()); }

    // ── 变长 ──────────────────────────────────────────────────────

    /** 返回 null 表示写入方写的就是 null(哨兵 0xFFFFFFFF),与空数组区分。 */
    public byte[] bytes() {
        need(4);
        int raw = (int) u32raw();
        if (raw == QccCanonicalWriter.NULL_LEN) return null;
        long len = raw & 0xFFFFFFFFL;
        if (len > QccCanonicalWriter.MAX_FIELD)
            throw new IllegalStateException("字段长度超过 MAX_FIELD: " + len);
        return fixed((int) len);
    }

    public String str() {
        byte[] b = bytes();
        return b == null ? null : new String(b, StandardCharsets.UTF_8);
    }

    public List<byte[]> list() {
        need(4);
        int raw = (int) u32raw();
        if (raw == QccCanonicalWriter.NULL_LEN) return null;
        long n = raw & 0xFFFFFFFFL;
        // 每个元素至少 4 字节长度前缀,以此上界拦截构造出来的巨大 count
        if (n > remaining() / 4L)
            throw new IllegalStateException("元素个数 " + n + " 超过剩余字节可能容纳的上限");
        List<byte[]> out = new ArrayList<>((int) n);
        for (long i = 0; i < n; i++) out.add(bytes());
        return out;
    }

    public List<String> strList() {
        List<byte[]> raw = list();
        if (raw == null) return null;
        List<String> out = new ArrayList<>(raw.size());
        for (byte[] b : raw) out.add(b == null ? null : new String(b, StandardCharsets.UTF_8));
        return out;
    }

    /**
     * 读 map。写入方保证 key 按 UTF-8 字节序升序,这里**校验**这一点 ——
     * 顺序错乱说明对方的实现没有遵守规范,必须当场发现,否则
     * 同一个逻辑 map 会有多种合法编码,execHash 就失去意义了。
     * 返回 LinkedHashMap,保持规范顺序。
     */
    public Map<String, byte[]> sortedMap() {
        need(4);
        int raw = (int) u32raw();
        if (raw == QccCanonicalWriter.NULL_LEN) return null;
        long n = raw & 0xFFFFFFFFL;
        if (n > remaining() / 8L)
            throw new IllegalStateException("map 条目数 " + n + " 超过剩余字节可能容纳的上限");
        Map<String, byte[]> out = new LinkedHashMap<>();
        String prev = null;
        for (long i = 0; i < n; i++) {
            String k = str();
            if (k == null) throw new IllegalStateException("map key 不允许为 null");
            if (prev != null && QccCanonicalWriter.compareUtf8(prev, k) >= 0)
                throw new IllegalStateException("map key 未按 UTF-8 字节序升序: '" + prev + "' 之后是 '" + k + "'");
            out.put(k, bytes());
            prev = k;
        }
        return out;
    }

    private long u32raw() {
        need(4);
        long v = ((long) (a[pos] & 0xFF) << 24)
               | ((a[pos + 1] & 0xFF) << 16)
               | ((a[pos + 2] & 0xFF) << 8)
               |  (a[pos + 3] & 0xFF);
        pos += 4;
        return v;
    }

    /** 必须在解析结束时调用:尾部有剩余字节即视为格式错误。 */
    public void finish() {
        if (remaining() != 0)
            throw new IllegalStateException("解析结束后仍有 " + remaining() + " 字节未消费,格式不匹配");
    }
}
