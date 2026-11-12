package qcc.name.epoch;

import qcc.name.codec.Sha3;
import qcc.name.core.NameState;
import qcc.name.state.OpLogStore;
import qcc.name.state.SparseMerkle;

import java.util.ArrayList;
import java.util.List;

/**
 * EpochBuilder —— 攒够就封口,算根,产出可锚定的 header。
 *
 * ═══ 封口条件必须是日志内容的纯函数 ═══════════════════════════════
 * 协议写的是:
 *     opCount >= 256 OR (blockHeight % 100 == 0 AND pendingOps > 0)
 *
 * 第二个条件有个陷阱:blockHeight 是**每条操作各自携带的**,不是全局时钟。
 * 如果按"外部定时器每隔一会儿检查一下当前链高度"来实现,那么边界就取决于
 * 定时器什么时候恰好跑到 —— 空闲期长一点短一点,封口位置就不同。
 * 重放者拿到一串日志,根本无从知道当初定时器是什么时候敲的,
 * **边界不同 → Merkle 树不同 → root 不同 → 判定为分歧。假阳性。**
 *
 * 所以这里的实现:高度维度只看**已进入日志的操作**的 admitHeight。
 *   触发条件 = 待封操作数 >= 256
 *            OR 最后一条待封操作的 admitHeight 跨过了 100 的倍数
 * 两个条件都只依赖日志内容,任何人重放都能算出同一组边界。
 *
 * 代价:空闲期不会自动封口。最后几条操作会一直挂着,直到攒够 256 条
 * 或者有新操作把 admitHeight 推过下一个 100 的边界。对 namespace 是
 * 可以接受的 —— 注册是低频操作,而且未封口 = 未锚定 = 收据里的 epochId
 * 还没兑现,用户看得见,不是静默丢失。
 *
 * 想要"空闲也定期封口",唯一可重放的做法是往日志里写一条**心跳操作**,
 * 让时间推进本身也成为日志的一部分。那是 v2 的事,现在不做。
 */
public final class EpochBuilder {

    private final String protocolHash;
    private final String instanceId;
    private final long   maxOpsPerEpoch;
    private final long   heightBoundary;

    private long   epochId;
    private String prevEpochHash;
    private long   nextStartSeq;

    public EpochBuilder(String protocolHash, String instanceId,
                        long maxOpsPerEpoch, long heightBoundary) {
        if (maxOpsPerEpoch < 1)  throw new IllegalArgumentException("maxOpsPerEpoch 至少为 1");
        if (heightBoundary < 1)  throw new IllegalArgumentException("heightBoundary 至少为 1");
        this.protocolHash   = protocolHash;
        this.instanceId     = instanceId;
        this.maxOpsPerEpoch = maxOpsPerEpoch;
        this.heightBoundary = heightBoundary;
        this.epochId        = 1;
        this.prevEpochHash  = EpochHeader.ZERO_HASH;
        this.nextStartSeq   = 1;
    }

    /** 从已有的最后一个 epoch 继续。节点重启后用它恢复。 */
    public void resumeFrom(EpochHeader last) {
        this.epochId       = last.epochId() + 1;
        this.prevEpochHash = last.epochHash();
        this.nextStartSeq  = last.endSeq() + 1;
    }

    public long epochId()      { return epochId; }
    public long nextStartSeq() { return nextStartSeq; }

    // ── 封口判定 ──────────────────────────────────────────────────

    /**
     * 是否该封口。只看日志:待封条数,以及首尾两条操作的 admitHeight
     * 是否跨过了 heightBoundary 的倍数。
     *
     * @return 该封口时返回结束 seq;否则返回 -1
     */
    public long shouldClose(OpLogStore log, java.util.function.LongUnaryOperator admitHeightOf) {
        long maxSeq = log.maxSeq();
        if (maxSeq < nextStartSeq) return -1;                 // 没有待封操作

        long pending = maxSeq - nextStartSeq + 1;
        if (pending >= maxOpsPerEpoch)
            return nextStartSeq + maxOpsPerEpoch - 1;          // 攒够条数,精确切在第 N 条

        long firstH = admitHeightOf.applyAsLong(nextStartSeq);
        long lastH  = admitHeightOf.applyAsLong(maxSeq);
        // 跨过 heightBoundary 的倍数即封口。整除判断用"跨越"而不是"等于",
        // 否则恰好落在倍数上的高度没有操作时就永远错过了。
        if (firstH / heightBoundary != lastH / heightBoundary) return maxSeq;

        return -1;
    }

    // ── 构造 header ───────────────────────────────────────────────

    /**
     * 封一个 epoch。调用方负责保证 [startSeq, endSeq] 已经全部 apply 进 state,
     * 且 execHash 是最后一条之后的值。
     *
     * @param opBytes 本 epoch 内每条操作写进日志的规范字节,按 seq 升序
     */
    public EpochHeader close(long endSeq, long endBlockHeight, List<byte[]> opBytes,
                             NameState state, byte[] execHash, String signerAddress) {
        long startSeq = nextStartSeq;
        if (endSeq < startSeq) throw new IllegalStateException("没有待封操作");
        if (opBytes.size() != endSeq - startSeq + 1)
            throw new IllegalStateException("操作字节数 " + opBytes.size()
                    + " 与区间长度 " + (endSeq - startSeq + 1) + " 不符");

        EpochHeader h = new EpochHeader(
                protocolHash, instanceId, epochId, prevEpochHash,
                startSeq, endSeq, endBlockHeight,
                Sha3.toHex(opsRoot(opBytes, startSeq)),
                Sha3.toHex(stateRoot(state)),
                Sha3.toHex(execHash),
                signerAddress);

        epochId++;
        prevEpochHash = h.epochHash();
        nextStartSeq  = endSeq + 1;
        return h;
    }

    // ── 两个根 ────────────────────────────────────────────────────

    /**
     * 本 epoch 操作列表的 Merkle 根。
     * 叶子位置取 SHA3(seq),而不是操作内容的哈希 —— 位置必须由**序号**决定,
     * 这样"第 n 条操作是什么"才是可证的。用内容哈希做位置的话,
     * 两条内容相同的操作会撞在同一个叶子上。
     */
    public static byte[] opsRoot(List<byte[]> opBytes, long startSeq) {
        List<SparseMerkle.Leaf> leaves = new ArrayList<>(opBytes.size());
        for (int i = 0; i < opBytes.size(); i++) {
            long seq = startSeq + i;
            byte[] key = Sha3.hash(u64(seq));
            byte[] val = Sha3.hash(new byte[]{0x00}, u64(seq), opBytes.get(i));
            leaves.add(new SparseMerkle.Leaf(key, val));
        }
        return SparseMerkle.root(leaves);
    }

    /** 用户证明"我的第 n 条操作确实被处理了"。 */
    public static qcc.name.state.MerkleProof proveOp(List<byte[]> opBytes, long startSeq, long seq) {
        List<SparseMerkle.Leaf> leaves = new ArrayList<>(opBytes.size());
        for (int i = 0; i < opBytes.size(); i++) {
            long s = startSeq + i;
            leaves.add(new SparseMerkle.Leaf(Sha3.hash(u64(s)),
                    Sha3.hash(new byte[]{0x00}, u64(s), opBytes.get(i))));
        }
        return SparseMerkle.prove(leaves, Sha3.hash(u64(seq)));
    }

    public static byte[] opLeafValue(long seq, byte[] opBytes) {
        return Sha3.hash(new byte[]{0x00}, u64(seq), opBytes);
    }

    public static byte[] opLeafKey(long seq) { return Sha3.hash(u64(seq)); }

    public static byte[] stateRoot(NameState state) {
        List<SparseMerkle.Leaf> leaves = new ArrayList<>();
        state.forEachLeaf((k, v) -> leaves.add(new SparseMerkle.Leaf(k, v)));
        return SparseMerkle.root(leaves);
    }

    private static byte[] u64(long v) {
        byte[] b = new byte[8];
        for (int i = 0; i < 8; i++) b[i] = (byte) (v >>> ((7 - i) * 8));
        return b;
    }
}
