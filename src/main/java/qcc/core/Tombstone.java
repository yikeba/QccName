package qcc;

/**
 * 墓碑:名字被 release 之后留下的记录。
 * 两个作用,缺一不可:
 *  1. 【冷却期】releasedHeight + releaseCooldownBlocks 之前不允许被别人抢注。
 *     域名行业的 redemption period 就是这么来的,是被无数误操作事故验证过的。
 *  2. 【世代号】nextIncarnation 让重新注册的名字与前任在密码学上可区分。
 *     没有它,Bob 抢到 alice 之后,所有指向 alice 的旧引用会静默解析到 Bob。
 * 墓碑永不物理删除 —— 它是历史的一部分,而且删掉之后冷却期就无从判断。
 * 十万级规模下墓碑的体积可以忽略。
 */
public final class Tombstone {

    public final long nextIncarnation;  // 下次注册用这个世代号
    public final long releasedHeight;   // release 时的 QCC 区块高度
    public final long seq;              // 产生本墓碑的操作 seq

    public Tombstone(long nextIncarnation, long releasedHeight, long seq) {
        if (nextIncarnation < 2)  throw new IllegalArgumentException("nextIncarnation 至少为 2: " + nextIncarnation);
        if (releasedHeight < 0)   throw new IllegalArgumentException("releasedHeight 不能为负: " + releasedHeight);
        if (seq < 1)              throw new IllegalArgumentException("seq 从 1 开始: " + seq);
        this.nextIncarnation = nextIncarnation;
        this.releasedHeight  = releasedHeight;
        this.seq             = seq;
    }

    /** 冷却期是否已过。用区块高度,不用墙钟 —— 墙钟不可重放。 */
    public boolean cooldownPassed(long currentHeight, long cooldownBlocks) {
        return currentHeight >= releasedHeight + cooldownBlocks;
    }

    public byte[] encode() {
        return new QccCanonicalWriter()
                .u64(nextIncarnation).u64(releasedHeight).u64(seq)
                .toBytes();
    }

    public static Tombstone decode(byte[] b) {
        QccCanonicalReader r = new QccCanonicalReader(b);
        Tombstone t = new Tombstone(r.u64(), r.u64(), r.u64());
        r.finish();
        return t;
    }

    @Override
    public String toString() {
        return "Tomb{nextInc=" + nextIncarnation + " h=" + releasedHeight + " seq=" + seq + "}";
    }
}
