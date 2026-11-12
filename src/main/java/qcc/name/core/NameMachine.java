package qcc.name.core;

import qcc.name.codec.Sha3;
import qcc.name.frame.NameFrame;
import qcc.name.op.ExpireOp;
import qcc.name.op.NameOp;
import qcc.name.op.RegisterOp;
import qcc.name.op.ReserveOp;
import qcc.name.op.UnregisterOp;
import qcc.name.protocol.NameProtocol;
import qcc.name.protocol.ReservedDoc;
import qcc.name.protocol.TagPolicy;

import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * 确定性核心：状态 + execHash 链。
 *
 * ═══ 纪律 ═══════════════════════════════════════════════════════
 * 不读墙钟、不做 IO、不用浮点、不迭代哈希容器、不含参数字面量。
 * 时间只来自帧里的 chainTime；质押事实只来自帧里的记录。
 *
 * ═══ 两个入口 ═══════════════════════════════════════════════════
 *   evaluate(in)  纯函数：按协议 ops[].checks 的顺序跑检查，返回第一个失败的结果码。
 *                 主节点用它决定"写进日志 / 入口丢弃"。不改状态。
 *   apply(frame)  重新 evaluate，要求结果码与帧里记录的一致、execHash 与本地重算一致，
 *                 然后修改状态、推进 execHash。主节点写帧、备节点收帧、重放器回放走的是同一条路径。
 */
public final class NameMachine {

    public static final Set<String> IMPLEMENTED_CHECKS = Set.of(
            "tsMonotonic", "tagOpen", "pledgeMet", "labelFormat", "notReserved", "notConfusable",
            "nameFree", "cooldownPassed", "addressFree", "nameExists", "holderMatches",
            "regSeqMatches", "credentialMatches", "pledgeGone",
            "reservePublisher", "reserveChain", "reserveDocument", "reserveSeq", "reserveHeight", "reserveKeepsNames");

    private interface Check { int run(NameMachine m, FrameInput in); }

    private static final Map<String, Check> CHECKS = new TreeMap<>();
    static {
        CHECKS.put("tsMonotonic", (m, in) ->
                in.op().timestamp > m.state.lastTs(in.op().address) ? ResultCode.OK : ResultCode.TS_NOT_MONOTONIC);
        CHECKS.put("tagOpen", (m, in) -> {                             // 已声明且 registration = open
            TagPolicy t = m.p.tag(in.op().tag());
            return t != null && t.open() ? ResultCode.OK : ResultCode.TAG_NOT_OPEN;
        });
        CHECKS.put("pledgeMet", (m, in) -> {
            TagPolicy t = m.p.tag(in.op().tag());
            return t != null && t.pledgeMet(in.pledgeExists(), in.pledgeAssetId(), in.pledgeAmount())
                    ? ResultCode.OK : ResultCode.PLEDGE_NOT_MET;
        });
        CHECKS.put("labelFormat", (m, in) ->
                m.rules.labelValid(in.op().label()) ? ResultCode.OK : ResultCode.LABEL_FORMAT);
        CHECKS.put("notReserved", (m, in) -> {                         // Reserved 表中的名字，及与之形近的名字
            if (m.state.reservedAddress(in.op().name) != null) return ResultCode.RESERVED;
            String k = m.rules.confusableKey(in.op().tag(), in.op().label());
            return m.state.reservedConfusableOwner(k) != null ? ResultCode.RESERVED : ResultCode.OK;
        });
        CHECKS.put("notConfusable", (m, in) -> {
            String owner = m.state.confusableOwner(m.rules.confusableKey(in.op().tag(), in.op().label()));
            return owner == null || owner.equals(in.op().name) ? ResultCode.OK : ResultCode.CONFUSABLE;
        });
        CHECKS.put("nameFree", (m, in) ->
                m.state.record(in.op().name) == null ? ResultCode.OK : ResultCode.NAME_TAKEN);
        CHECKS.put("cooldownPassed", (m, in) -> {
            Tombstone t = m.state.tomb(in.op().name);
            if (t == null) return ResultCode.OK;
            long elapsed = in.chainTime() - t.releasedTime();
            return elapsed >= m.p.cooldownMs ? ResultCode.OK : ResultCode.COOLDOWN;
        });
        CHECKS.put("addressFree", (m, in) ->
                m.state.holderName(in.op().tag(), in.op().address) == null ? ResultCode.OK : ResultCode.ADDRESS_HAS_NAME);
        CHECKS.put("nameExists", (m, in) ->
                m.state.record(in.op().name) != null ? ResultCode.OK : ResultCode.NAME_NOT_FOUND);
        CHECKS.put("holderMatches", (m, in) -> {
            NameRecord r = m.state.record(in.op().name);
            return r != null && r.address().equals(in.op().address) ? ResultCode.OK : ResultCode.HOLDER_MISMATCH;
        });
        CHECKS.put("regSeqMatches", (m, in) -> {
            NameRecord r = m.state.record(in.op().name);
            return r != null && in.op() instanceof UnregisterOp u && u.regSeq == r.regSeq()
                    ? ResultCode.OK : ResultCode.REGSEQ_MISMATCH;
        });
        CHECKS.put("credentialMatches", (m, in) -> {
            NameRecord r = m.state.record(in.op().name);
            return r != null && in.op() instanceof ExpireOp e && e.credentialHash.equals(r.credentialHash())
                    ? ResultCode.OK : ResultCode.CREDENTIAL_MISMATCH;
        });
        CHECKS.put("pledgeGone", (m, in) ->
                in.pledgeExists() ? ResultCode.PLEDGE_STILL_VALID : ResultCode.OK);
        // ── reserve：协议发布者的 Reserved 文档 ──
        CHECKS.put("reservePublisher", (m, in) ->
                m.p.reservedEnabled() && in.op().address.equals(m.p.reservedPublisher) ? ResultCode.OK : ResultCode.RESERVE_PUBLISHER);
        CHECKS.put("reserveChain", (m, in) ->
                in.op().chain.equals(m.p.chain) ? ResultCode.OK : ResultCode.RESERVE_CHAIN);
        CHECKS.put("reserveDocument", (m, in) -> m.documentProblem(reserve(in)) == null ? ResultCode.OK : ResultCode.RESERVE_DOCUMENT);
        CHECKS.put("reserveSeq", (m, in) -> {
            ReservedDoc d = reserve(in).doc();
            return d != null && d.seq == m.state.reservedSeq() + 1 && d.prevTx.equals(m.state.reservedTx())
                    ? ResultCode.OK : ResultCode.RESERVE_SEQ;
        });
        CHECKS.put("reserveHeight", (m, in) ->
                reserve(in).height > m.state.reservedHeight() ? ResultCode.OK : ResultCode.RESERVE_HEIGHT);
        CHECKS.put("reserveKeepsNames", (m, in) -> {
            ReservedDoc d = reserve(in).doc();
            if (d == null) return ResultCode.RESERVE_DROPS_NAME;
            for (String r : d.release) if (m.state.reservedAddress(r) == null) return ResultCode.RESERVE_DROPS_NAME;
            for (String old : m.state.reserved.keySet())
                if (!d.names.containsKey(old) && !d.release.contains(old)) return ResultCode.RESERVE_DROPS_NAME;
            return ResultCode.OK;
        });
        if (!CHECKS.keySet().equals(IMPLEMENTED_CHECKS)) throw new ExceptionInInitializerError("CHECKS 表不完整");
    }

    private static ReserveOp reserve(FrameInput in) {
        if (!(in.op() instanceof ReserveOp r)) throw new IllegalStateException("reserve 检查用在了非 reserve 操作上");
        return r;
    }

    /** Reserved 文档的协议级问题（大小、协议 hash、tag、label 规则）；没有问题返回 null。 */
    public String documentProblem(ReserveOp r) {
        if (r.documentSize() > p.reservedMaxBytes) return "文档超过 " + p.reservedMaxBytes + " 字节";
        ReservedDoc d = r.doc();
        if (d == null) return "结构错误：" + r.parseError();
        if (!d.nameProtocolHash.equals(p.protocolHash)) return "nameProtocolHash 不是本协议";
        for (String n : d.names.keySet()) { String e = nameProblem(n); if (e != null) return e; }
        for (String n : d.release)        { String e = nameProblem(n); if (e != null) return e; }
        return null;
    }

    private String nameProblem(String n) {
        if (p.tag(ReservedDoc.tagOf(n)) == null) return n + "：tag 未在协议中声明";
        if (!rules.labelValid(ReservedDoc.labelOf(n))) return n + "：label 不符合 labelFormat";
        return null;
    }

    private final NameProtocol p;
    private final NameRules    rules;
    private final NameState    state = new NameState();
    private byte[] execHash;
    private long   lastSeq;
    private long   lastChainTime;

    public NameMachine(NameProtocol p, String instanceId) {
        this.p = p;
        this.rules = new NameRules(p);
        this.execHash = NameFrame.genesisExecHash(p.protocolHashBytes(), instanceId, p.reservedPublisher);
    }

    // ── 纯函数评估 ────────────────────────────────────────────────

    public int evaluate(FrameInput in) {
        NameProtocol.OpSpec spec = p.op(in.op().typeCode());
        if (spec == null) throw new IllegalStateException("未声明的操作 " + in.op().typeCode());
        for (String name : spec.checks()) {
            int r = CHECKS.get(name).run(this, in);
            if (r != ResultCode.OK) return r;
        }
        return ResultCode.OK;
    }

    /** 该结果是否应当写入日志（OK，或协议 loggedRejections 中列出的拒绝）。 */
    public boolean loggable(NameOp op, int code) {
        return code == ResultCode.OK || p.op(op.typeCode()).loggedRejections().contains(code);
    }

    // ── 应用一帧 ──────────────────────────────────────────────────

    /**
     * 应用一帧。任何不一致都抛 IllegalStateException —— 不一致意味着日志损坏、
     * 主节点作恶或实现分歧，应停机排查，不能编造一个结果把它固化进历史。
     */
    public void apply(NameFrame f) {
        if (f.seq != lastSeq + 1)
            throw new IllegalStateException("seq 不连续：期望 " + (lastSeq + 1) + " 实际 " + f.seq);
        if (f.chainTime < lastChainTime)
            throw new IllegalStateException("chainTime 倒退 @seq=" + f.seq);
        NameOp op = f.op();
        boolean signed = p.op(op.typeCode()).userSigned();
        if (signed != op.userSigned()) throw new IllegalStateException("op 签名属性与协议不符");
        if (!signed && !Sha3.equalsConstantTime(f.sigHash, Sha3.zero32()))
            throw new IllegalStateException("系统操作的 sigHash 必须为全 0 @seq=" + f.seq);

        FrameInput in = f.input();
        int code = evaluate(in);
        if (code != f.result)
            throw new IllegalStateException("结果码分歧 @seq=" + f.seq + "：帧记录 " + f.result + "，本地重算 " + code);
        if (!loggable(op, code))
            throw new IllegalStateException("帧记录了一个不应进入日志的结果 " + code + " @seq=" + f.seq);
        if (!f.execMatches(execHash))
            throw new IllegalStateException("execHash 分歧 @seq=" + f.seq);

        mutate(in, code);
        execHash = f.execHash.clone();
        lastSeq = f.seq;
        lastChainTime = f.chainTime;
    }

    private void mutate(FrameInput in, int code) {
        NameOp op = in.op();
        String tag = op.tag();
        if (op instanceof RegisterOp r) {
            state.lastTs.put(op.address, op.timestamp);            // 进入日志的用户操作都推进 lastTs
            if (code != ResultCode.OK) return;
            state.records.put(op.name, new NameRecord(op.address, r.credentialHash, in.seq(), in.chainTime()));
            state.holders.put(tag + "|" + op.address, op.name);
            state.confusable.put(rules.confusableKey(tag, op.label()), op.name);
            state.tombs.remove(op.name);
        } else if (op instanceof UnregisterOp || op instanceof ExpireOp) {
            if (op.userSigned()) state.lastTs.put(op.address, op.timestamp);
            if (code != ResultCode.OK) return;
            NameRecord rec = state.records.remove(op.name);
            state.holders.remove(tag + "|" + rec.address());
            state.confusable.remove(rules.confusableKey(tag, op.label()));
            state.tombs.put(op.name, new Tombstone(in.chainTime(), rec.regSeq()));
        } else if (op instanceof ReserveOp r) {
            if (code != ResultCode.OK) return;
            ReservedDoc d = r.doc();
            for (String n : d.names.keySet()) {                       // 同名的已注册名字：移除并进入冷却期
                NameRecord rec = state.records.remove(n);
                if (rec == null) continue;
                String t = ReservedDoc.tagOf(n);
                state.holders.remove(t + "|" + rec.address());
                state.confusable.remove(rules.confusableKey(t, ReservedDoc.labelOf(n)));
                state.tombs.put(n, new Tombstone(in.chainTime(), rec.regSeq()));
            }
            state.reserved.clear();
            state.reserved.putAll(d.names);
            state.reservedConfusable.clear();
            for (String n : d.names.keySet())
                state.reservedConfusable.putIfAbsent(rules.confusableKey(ReservedDoc.tagOf(n), ReservedDoc.labelOf(n)), n);
            state.reservedHistory.put(d.seq, new NameState.ReservedVersion(d.seq, r.reservedTx, r.height, in.seq(),
                    in.chainTime(), d.documentHash));
        } else {
            throw new IllegalStateException("未实现的操作类型 " + op.typeCode());
        }
    }

    // ── 只读 ──────────────────────────────────────────────────────

    public NameState state()        { return state; }
    public byte[]    execHash()     { return execHash.clone(); }
    public String    execHex()      { return Sha3.toHex(execHash); }
    public long      lastSeq()      { return lastSeq; }
    public long      lastChainTime(){ return lastChainTime; }
    public NameProtocol protocol()  { return p; }
}
