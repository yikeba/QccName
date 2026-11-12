package qcc.name.core;

import qcc.name.codec.QccCanonicalWriter;
import qcc.name.codec.Sha3;

import java.util.Map;
import java.util.TreeMap;

/**
 * 由帧日志重放得出的全部状态。全部 TreeMap，按 UTF-8 字节序 —— 任何遍历顺序都确定。
 *
 *   records    name              → NameRecord
 *   holders    tag|address       → name          （同一地址在同一 tag 下至多一个名称）
 *   lastTs     address           → 最近一条进入日志的用户操作的 timestamp（删除名称后保留）
 *   tombs      name              → Tombstone     （冷却期）
 *   confusable tag|normLabel     → name
 *   reserved   name              → 地址（空串 = 保留但不绑定）     当前生效的 Reserved 表，优先于 records
 *   reservedConfusable tag|normLabel → 保留名                   保留名的同形字索引（注册时拦截形近名）
 *   reservedHistory seq → reservedTx | height | 日志 seq        全部历史版本，按 seq 递增
 *
 * 只能通过 NameMachine 修改。
 */
public final class NameState {

    final TreeMap<String, NameRecord> records    = new TreeMap<>(QccCanonicalWriter::compareUtf8);
    final TreeMap<String, String>     holders    = new TreeMap<>(QccCanonicalWriter::compareUtf8);
    final TreeMap<String, Long>       lastTs     = new TreeMap<>(QccCanonicalWriter::compareUtf8);
    final TreeMap<String, Tombstone>  tombs      = new TreeMap<>(QccCanonicalWriter::compareUtf8);
    final TreeMap<String, String>     confusable = new TreeMap<>(QccCanonicalWriter::compareUtf8);
    final TreeMap<String, String>     reserved   = new TreeMap<>(QccCanonicalWriter::compareUtf8);
    final TreeMap<String, String>     reservedConfusable = new TreeMap<>(QccCanonicalWriter::compareUtf8);
    final TreeMap<Long, ReservedVersion> reservedHistory = new TreeMap<>();

    /** 一个已生效的 Reserved 版本。logSeq = 写入它的 reserve 帧序号（L1 证据位置）。 */
    public record ReservedVersion(long seq, String tx, long height, long logSeq, long chainTime, String documentHash) {}

    public NameRecord record(String name)               { return records.get(name); }
    public String     holderName(String tag, String a)  { return holders.get(tag + "|" + a); }
    public long       lastTs(String address)            { return lastTs.getOrDefault(address, 0L); }
    public Tombstone  tomb(String name)                 { return tombs.get(name); }
    public String     confusableOwner(String key)       { return confusable.get(key); }
    public int        nameCount()                       { return records.size(); }

    /** 名称在当前 Reserved 表中时返回其地址（空串 = 保留但不绑定）；不在表中返回 null。 */
    public String     reservedAddress(String name)      { return reserved.get(name); }
    public String     reservedConfusableOwner(String k) { return reservedConfusable.get(k); }
    public java.util.SortedMap<String, String> reservedTable() { return java.util.Collections.unmodifiableSortedMap(reserved); }
    public java.util.List<ReservedVersion> reservedHistory()   { return java.util.List.copyOf(reservedHistory.values()); }
    /** 当前生效版本；还没有任何版本返回 null。 */
    public ReservedVersion reservedCurrent()            { return reservedHistory.isEmpty() ? null : reservedHistory.lastEntry().getValue(); }
    public long       reservedSeq()                     { ReservedVersion v = reservedCurrent(); return v == null ? 0 : v.seq(); }
    public String     reservedTx()                      { ReservedVersion v = reservedCurrent(); return v == null ? "" : v.tx(); }
    public long       reservedHeight()                  { ReservedVersion v = reservedCurrent(); return v == null ? 0 : v.height(); }
    public boolean    reservedApplied(String tx)        { for (ReservedVersion v : reservedHistory.values()) if (v.tx().equals(tx)) return true; return false; }

    /**
     * 全量状态摘要（排序哈希链）。不进帧、不进 execHash；
     * 用于节点之间、重放结果之间做交叉核对：execHash 一致而它不一致，说明状态机实现有 bug。
     */
    public String digest() {
        QccCanonicalWriter w = new QccCanonicalWriter(4096);
        for (Map.Entry<String, NameRecord> e : records.entrySet())
            w.u8(1).str(e.getKey()).str(e.getValue().address()).str(e.getValue().credentialHash())
             .u64(e.getValue().regSeq()).u64(e.getValue().regTime());
        for (Map.Entry<String, String> e : holders.entrySet())    w.u8(2).str(e.getKey()).str(e.getValue());
        for (Map.Entry<String, Long> e : lastTs.entrySet())       w.u8(3).str(e.getKey()).u64(e.getValue());
        for (Map.Entry<String, Tombstone> e : tombs.entrySet())   w.u8(4).str(e.getKey()).u64(e.getValue().releasedTime()).u64(e.getValue().regSeq());
        for (Map.Entry<String, String> e : confusable.entrySet()) w.u8(5).str(e.getKey()).str(e.getValue());
        for (Map.Entry<String, String> e : reserved.entrySet())   w.u8(6).str(e.getKey()).str(e.getValue());
        for (Map.Entry<String, String> e : reservedConfusable.entrySet()) w.u8(7).str(e.getKey()).str(e.getValue());
        for (ReservedVersion v : reservedHistory.values())
            w.u8(8).u64(v.seq()).str(v.tx()).u64(v.height()).u64(v.logSeq()).u64(v.chainTime()).str(v.documentHash());
        return Sha3.toHex(Sha3.hash(w.toBytes()));
    }

    @Override
    public String toString() {
        return "NameState{names=" + records.size() + " tombs=" + tombs.size() + " addrs=" + lastTs.size()
                + " reserved=" + reserved.size() + "@seq" + reservedSeq() + "}";
    }
}
