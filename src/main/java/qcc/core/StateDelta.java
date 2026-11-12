package qcc;

import qcc.core.ForwardRecord;
import qcc.core.Tombstone;
import qcc.data.QccCanonicalReader;
import qcc.data.QccCanonicalWriter;
import qcc.util.Sha3;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * StateDelta —— 一条操作对状态造成的全部变更。
 * 这个对象进 execHash,所以它的编码必须**唯一**:同一组变更,
 * 无论 handler 以什么顺序 emit,必须产出完全相同的字节。
 * 因此 encode() 会先排序,不依赖 emit 顺序。
 * 排序键:(typeCode, key 的 UTF-8 字节序)。两者组合在任何合法 delta 里唯一
 * —— 同一个 key 在同一条操作里不会既 PUT 又 DEL(那是逻辑错误,
 * 由 assertNoConflict() 拦截)。
 * 被拒绝的操作产生**空 delta**,但仍然推进 execHash(带上 resultCode)。
 * 这一点很关键:如果只有成功的操作进 hash,那么"运营方悄悄丢弃 Alice 的
 * 注册"和"Alice 的注册因重名被正当拒绝"会产生完全相同的 execHash,
 * 审查在链上不可区分。带上 resultCode 之后,拒绝理由本身变成可验证的。
 */
public final class StateDelta {

    public static final int PUT_FORWARD   = 1;
    public static final int DEL_FORWARD   = 2;
    public static final int PUT_REVERSE   = 3;
    public static final int DEL_REVERSE   = 4;
    public static final int PUT_TOMBSTONE = 5;
    public static final int PUT_CONFUSABLE = 6;
    public static final int DEL_CONFUSABLE = 7;

    /** 单条变更。key 对 forward/tombstone 是 nameHash 的 hex,对 reverse 是地址。 */
    public record Entry(int type, String key, byte[] value) { }

    private final List<Entry> entries;

    private StateDelta(List<Entry> entries) { this.entries = entries; }

    public static StateDelta empty() { return new StateDelta(List.of()); }

    public boolean isEmpty()      { return entries.isEmpty(); }
    public List<Entry> entries()  { return List.copyOf(entries); }
    public int size()             { return entries.size(); }

    // ── 构造 ──────────────────────────────────────────────────────

    public static final class Builder {
        private final List<Entry> list = new ArrayList<>();

        public Builder putForward(String nameHashHex, ForwardRecord rec) {
            requireHash(nameHashHex);
            list.add(new Entry(PUT_FORWARD, nameHashHex, rec.encode()));
            return this;
        }

        public Builder delForward(String nameHashHex) {
            requireHash(nameHashHex);
            list.add(new Entry(DEL_FORWARD, nameHashHex, new byte[0]));
            return this;
        }

        public Builder putReverse(String address, String nameHashHex) {
            requireHash(nameHashHex);
            if (address == null || address.isEmpty())
                throw new IllegalArgumentException("address 不能为空");
            list.add(new Entry(PUT_REVERSE, address,
                    nameHashHex.getBytes(StandardCharsets.UTF_8)));
            return this;
        }

        public Builder delReverse(String address) {
            if (address == null || address.isEmpty())
                throw new IllegalArgumentException("address 不能为空");
            list.add(new Entry(DEL_REVERSE, address, new byte[0]));
            return this;
        }

        public Builder putConfusable(String normHashHex, String nameHashHex) {
            requireHash(normHashHex); requireHash(nameHashHex);
            list.add(new Entry(PUT_CONFUSABLE, normHashHex,
                    nameHashHex.getBytes(StandardCharsets.UTF_8)));
            return this;
        }

        public Builder delConfusable(String normHashHex) {
            requireHash(normHashHex);
            list.add(new Entry(DEL_CONFUSABLE, normHashHex, new byte[0]));
            return this;
        }

        public Builder putTombstone(String nameHashHex, Tombstone t) {
            requireHash(nameHashHex);
            list.add(new Entry(PUT_TOMBSTONE, nameHashHex, t.encode()));
            return this;
        }

        public StateDelta build() {
            List<Entry> sorted = new ArrayList<>(list);
            sorted.sort((a, b) -> {
                int c = Integer.compare(a.type(), b.type());
                if (c != 0) return c;
                return QccCanonicalWriter.compareUtf8(a.key(), b.key());
            });
            assertNoConflict(sorted);
            return new StateDelta(List.copyOf(sorted));
        }

        private static void requireHash(String hex) {
            if (!Sha3.isHex32(hex))
                throw new IllegalArgumentException("nameHash 必须是 64 字符 hex: " + hex);
        }

        /**
         * 同一条操作里,同一个 (type, key) 不能出现两次;
         * 同一个 key 也不能既 PUT 又 DEL。这类冲突是 handler 的逻辑错误,
         * 必须当场炸出来 —— 让它进 execHash 就是把 bug 固化进历史。
         */
        private static void assertNoConflict(List<Entry> sorted) {
            for (int i = 1; i < sorted.size(); i++) {
                Entry a = sorted.get(i - 1), b = sorted.get(i);
                if (a.type() == b.type() && a.key().equals(b.key()))
                    throw new IllegalStateException(
                            "同一条操作里出现重复变更 type=" + a.type() + " key=" + a.key());
            }
            for (Entry e : sorted) {
                int opposite = switch (e.type()) {
                    case PUT_FORWARD -> DEL_FORWARD;
                    case DEL_FORWARD -> PUT_FORWARD;
                    case PUT_REVERSE -> DEL_REVERSE;
                    case DEL_REVERSE -> PUT_REVERSE;
                    case PUT_CONFUSABLE -> DEL_CONFUSABLE;
                    case DEL_CONFUSABLE -> PUT_CONFUSABLE;
                    default -> -1;
                };
                if (opposite < 0) continue;
                for (Entry o : sorted)
                    if (o.type() == opposite && o.key().equals(e.key()))
                        throw new IllegalStateException(
                                "同一条操作里对同一 key 既 PUT 又 DEL: " + e.key());
            }
        }
    }

    public static Builder builder() { return new Builder(); }

    // ── 规范编码 ──────────────────────────────────────────────────

    public byte[] encode() {
        QccCanonicalWriter w = new QccCanonicalWriter();
        w.u32(entries.size());
        for (Entry e : entries) {
            w.u8(e.type());
            w.str(e.key());
            w.bytes(e.value());
        }
        return w.toBytes();
    }

    public static StateDelta decode(byte[] b) {
        QccCanonicalReader r = new QccCanonicalReader(b);
        long n = r.u32();
        List<Entry> out = new ArrayList<>((int) n);
        String prevKey = null;
        int prevType = -1;
        for (long i = 0; i < n; i++) {
            int type   = r.u8();
            String key = r.str();
            byte[] val = r.bytes();
            // 校验编码方确实排过序 —— 同一个 delta 只能有一种合法编码
            if (prevType >= 0) {
                int c = Integer.compare(prevType, type);
                if (c > 0 || (c == 0 && QccCanonicalWriter.compareUtf8(prevKey, key) >= 0))
                    throw new IllegalStateException("StateDelta 条目未按 (type, key) 升序");
            }
            out.add(new Entry(type, key, val));
            prevType = type; prevKey = key;
        }
        r.finish();
        return new StateDelta(List.copyOf(out));
    }

    @Override
    public String toString() { return "StateDelta{" + entries.size() + " entries}"; }
}
