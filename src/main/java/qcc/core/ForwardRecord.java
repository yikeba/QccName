package qcc;


import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 正向记录:nameHash → 这个名字的全部状态。
 * 不可变。任何变更都产生新实例 —— 状态机是纯函数,不允许原地修改。
 * addresses 的顺序是**插入顺序**,不排序。这仍然是确定的:
 * 顺序由操作日志决定,而日志对所有重放者都一样。排序反而会丢失
 * "谁先绑定"这个信息,而 unbind 之后重新 bind 需要它来复现。
 * incarnation:名字被 release 后重新注册时 +1。所有引用必须带上它,
 * 否则前任持有者的外链会在新持有者接手后静默指向新人 —— 钓鱼接管。
 */
public final class ForwardRecord {

    public final List<String> addresses;   // 已绑定地址,插入序
    public final String       owner;       // 必须是 addresses 之一
    public final long         incarnation; // 第几代,从 1 开始
    public final long         seq;         // 最后一次修改本记录的操作 seq

    public ForwardRecord(List<String> addresses, String owner, long incarnation, long seq) {
        if (addresses == null || addresses.isEmpty())
            throw new IllegalArgumentException("addresses 不能为空 —— 账户至少绑定一个地址");
        if (owner == null || owner.isEmpty())
            throw new IllegalArgumentException("owner 不能为空");
        if (!addresses.contains(owner))
            throw new IllegalArgumentException("owner 必须是已绑定地址之一: " + owner);
        if (incarnation < 1) throw new IllegalArgumentException("incarnation 从 1 开始: " + incarnation);
        if (seq < 1)         throw new IllegalArgumentException("seq 从 1 开始: " + seq);
        this.addresses   = List.copyOf(addresses);
        this.owner       = owner;
        this.incarnation = incarnation;
        this.seq         = seq;
    }

    // ── 变更:全部返回新实例 ──────────────────────────────────────

    public ForwardRecord withAddressAdded(String addr, long atSeq) {
        if (addresses.contains(addr)) throw new IllegalArgumentException("地址已绑定: " + addr);
        List<String> next = new ArrayList<>(addresses);
        next.add(addr);
        return new ForwardRecord(next, owner, incarnation, atSeq);
    }

    public ForwardRecord withAddressRemoved(String addr, long atSeq) {
        if (!addresses.contains(addr)) throw new IllegalArgumentException("地址未绑定: " + addr);
        if (addr.equals(owner))        throw new IllegalArgumentException("不能解绑 owner,请先转移所有权");
        List<String> next = new ArrayList<>(addresses);
        next.remove(addr);
        return new ForwardRecord(next, owner, incarnation, atSeq);
    }

    public ForwardRecord withOwner(String newOwner, long atSeq) {
        return new ForwardRecord(addresses, newOwner, incarnation, atSeq);
    }

    public boolean isLastAddress(String addr) {
        return addresses.size() == 1 && addresses.get(0).equals(addr);
    }

    // ── 规范编码:Merkle 叶子与 stateDelta 都用这个 ────────────────

    public byte[] encode() {
        return new QccCanonicalWriter()
                .strList(addresses)
                .str(owner)
                .u64(incarnation)
                .u64(seq)
                .toBytes();
    }

    public static ForwardRecord decode(byte[] b) {
        QccCanonicalReader r = new QccCanonicalReader(b);
        List<String> addrs = r.strList();
        String owner       = r.str();
        long inc           = r.u64();
        long seq           = r.u64();
        r.finish();
        return new ForwardRecord(addrs == null ? Collections.emptyList() : addrs, owner, inc, seq);
    }

    @Override
    public String toString() {
        return "Forward{owner=" + owner + " addrs=" + addresses.size()
                + " inc=" + incarnation + " seq=" + seq + "}";
    }
}
