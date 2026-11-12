package qcc.name.epoch;

import qcc.name.codec.QccCanonicalReader;
import qcc.name.codec.QccCanonicalWriter;
import qcc.name.codec.Sha3;

/**
 * EpochHeader —— 锚定到 QCC 主链的那个对象。
 *
 * 这是 namespace 对外做出的唯一承诺:"截至 seq=endSeq,我的状态是这样,
 * 执行过程是这样"。锚定之后就改不了了 —— 改任何一条历史,execHash 就对不上。
 *
 * ═══ 为什么 opsRoot 和 stateRoot 两个都要 ═══════════════════════
 *   opsRoot    本 epoch 内操作列表的 Merkle 根
 *              → 用户证明"我的请求被处理了"(配合 leader 签的收据)
 *   stateRoot  epoch 结束时全量状态的 Merkle 根
 *              → 用户证明"我的名字现在存在/不存在"
 *
 * 只有 stateRoot 的话,用户能证明结果但证明不了自己的请求进过系统 ——
 * 运营方可以悄悄丢弃请求,状态自洽,查无可查。
 * 只有 opsRoot 的话,反过来:能证明请求被收了,但证明不了最终归属。
 *
 * ═══ endBlockHeight 是一条交叉约束 ═══════════════════════════════
 * 本 epoch 内所有操作的 admitHeight 必须 <= endBlockHeight。
 * leader 可以在单条 admitHeight 上撒谎,但整个 epoch 被这个上界钉住,
 * 而 endBlockHeight 又要跟链上的实际高度对得上 —— 伪造会被独立发现。
 *
 * ═══ 签名者不在 header 里做轮换 ═══════════════════════════════════
 * signerAddress 的合法性由**链上**判定:该地址在 endBlockHeight 时刻
 * 是否持有本 tag 下的有效 AuthPledge。所以主备切换、密钥泄露后的吊销,
 * 全部走链上的授权质押 lock/unlock,日志里没有"轮换"这种操作。
 * 这也意味着双签(主备同时认为自己是主)是**可证的故障**:
 * 拿到两个 epochId 相同而 execHash 不同的 header 就是证据。
 */
public record EpochHeader(
        String protocolHash,     // 引导协议身份,绑定这是哪套规则
        String instanceId,       // 根 tag 的 TagRule 交易 hash
        long   epochId,          // 从 1 开始,连续
        String prevEpochHash,    // 前一个 epoch 的 epochHash;首个为全零
        long   startSeq,         // 本 epoch 的第一条操作(含)
        long   endSeq,           // 本 epoch 的最后一条操作(含)
        long   endBlockHeight,   // 封口时观察到的链高度,约束本 epoch 全部 admitHeight
        String opsRoot,          // Merkle(本 epoch 有序操作列表)
        String stateRoot,        // Merkle(epoch 结束时的全量状态)
        String execHash,         // 本 epoch 最后一条操作推进后的 execHash
        String signerAddress) {  // 签名者;合法性由链上 AuthPledge 判定

    public static final String ZERO_HASH =
            "0000000000000000000000000000000000000000000000000000000000000000";

    public EpochHeader {
        require(Sha3.isHex32(protocolHash),  "protocolHash");
        require(Sha3.isHex32(instanceId),    "instanceId");
        require(Sha3.isHex32(prevEpochHash), "prevEpochHash");
        require(Sha3.isHex32(opsRoot),       "opsRoot");
        require(Sha3.isHex32(stateRoot),     "stateRoot");
        require(Sha3.isHex32(execHash),      "execHash");
        if (epochId < 1)          throw new IllegalArgumentException("epochId 从 1 开始: " + epochId);
        if (startSeq < 1)         throw new IllegalArgumentException("startSeq 从 1 开始: " + startSeq);
        if (endSeq < startSeq)    throw new IllegalArgumentException("endSeq < startSeq");
        if (endBlockHeight < 0)   throw new IllegalArgumentException("endBlockHeight 不能为负");
        if (signerAddress == null || signerAddress.isEmpty())
            throw new IllegalArgumentException("signerAddress 不能为空");
    }

    private static void require(boolean ok, String field) {
        if (!ok) throw new IllegalArgumentException(field + " 必须是 64 字符 hex");
    }

    public long opCount() { return endSeq - startSeq + 1; }

    // ── 规范编码 ──────────────────────────────────────────────────

    /** 不含签名的规范字节。epochHash 和签名都对它计算。 */
    public byte[] encodeUnsigned() {
        return new QccCanonicalWriter()
                .hash32Hex(protocolHash)
                .hash32Hex(instanceId)
                .u64(epochId)
                .hash32Hex(prevEpochHash)
                .u64(startSeq)
                .u64(endSeq)
                .u64(endBlockHeight)
                .hash32Hex(opsRoot)
                .hash32Hex(stateRoot)
                .hash32Hex(execHash)
                .str(signerAddress)
                .toBytes();
    }

    /** epochHash = SHA3-256(不含签名的规范字节)。链接下一个 epoch 用这个。 */
    public String epochHash() { return Sha3.toHex(Sha3.hash(encodeUnsigned())); }

    public static EpochHeader decodeUnsigned(byte[] b) {
        QccCanonicalReader r = new QccCanonicalReader(b);
        EpochHeader h = new EpochHeader(
                r.hash32Hex(), r.hash32Hex(), r.u64(), r.hash32Hex(),
                r.u64(), r.u64(), r.u64(),
                r.hash32Hex(), r.hash32Hex(), r.hash32Hex(), r.str());
        r.finish();
        return h;
    }

    /**
     * 与前一个 epoch 的链接是否成立。
     * 三条都要查:epochId 连续、seq 无缝、高度不倒退。
     * 少查一条就能被伪造出"看起来连续"的历史。
     */
    public boolean linksTo(EpochHeader prev) {
        if (prev == null)
            return epochId == 1 && ZERO_HASH.equals(prevEpochHash) && startSeq == 1;
        return epochId == prev.epochId() + 1
            && prevEpochHash.equalsIgnoreCase(prev.epochHash())
            && startSeq == prev.endSeq() + 1
            && endBlockHeight >= prev.endBlockHeight()
            && instanceId.equalsIgnoreCase(prev.instanceId())
            && protocolHash.equalsIgnoreCase(prev.protocolHash());
    }

    @Override
    public String toString() {
        return "Epoch#" + epochId + "[seq " + startSeq + ".." + endSeq
                + " h=" + endBlockHeight + " exec=" + execHash.substring(0, 12) + "..]";
    }
}
