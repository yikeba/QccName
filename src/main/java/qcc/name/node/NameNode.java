package qcc.name.node;

import qcc.name.chain.ChainUnavailableException;
import qcc.name.chain.ChainView;
import qcc.name.chain.PledgeFact;
import qcc.name.codec.Sha3;
import qcc.name.core.FrameInput;
import qcc.name.core.NameMachine;
import qcc.name.core.NameRecord;
import qcc.name.core.ResultCode;
import qcc.name.crypto.MlDsa87;
import qcc.name.frame.Ack;
import qcc.name.frame.FramePacket;
import qcc.name.frame.Heartbeat;
import qcc.name.frame.NameFrame;
import qcc.name.op.ExpireOp;
import qcc.name.op.NameOp;
import qcc.name.op.RegisterOp;
import qcc.name.protocol.NameProtocol;
import qcc.name.store.FrameStore;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * namespace 节点：主节点受理写入并推送帧，备节点校验、落盘、确认。
 *
 * ═══ 写入流程（主节点）═══════════════════════════════════════════
 *   1. 入口：格式 → chain → 时间窗 → 幂等（同一 opHash 返回原结果）→ 链上取公钥验签
 *   2. 取链上事实：chainTime；register 再查授权质押（三要素）
 *   3. 核心 evaluate；撞上 nameTaken / addressHasName 时检查原持有者的质押，
 *      已撤销则先写一条 expire 帧回收，再重新 evaluate
 *   4. 不在 loggedRejections 中的拒绝 → 入口丢弃，不进日志
 *   5. 构帧 → 核心 apply → 落盘 → 推送给所有备节点 → 统计 ACK
 *      ACK ≥ minBackupAcks 才算生效；不足返回 PENDING（帧已在主节点日志中，备节点追平后生效）
 *
 * ═══ 收帧（备节点）════════════════════════════════════════════════
 *   term 低于本地 → 拒收（旧主的帧）；seq 有缺口 → 先向发送方拉取补齐；
 *   验签（链上公钥）→ 核心 apply（结果码与 execHash 必须一致）→ 落盘 → ACK
 *
 * ═══ 接班（P1 两节点，手动）═════════════════════════════════════
 *   promote(newTerm)：order[newTerm mod N] 必须是本节点。
 *   旧主恢复：rejoinFrom(peer) —— 清空本地数据，全量重新同步，不抢回主位。
 *
 * 线程模型：写入与收帧串行（节点锁）。pull / heartbeat 不取节点锁：
 * 主节点推帧时持有自己的锁，备节点若发现缺口会反向拉取，取锁会互相等待到超时。
 * 日志是权威，状态由重放得出。
 */
public final class NameNode implements AutoCloseable {

    private final NodeConfig   cfg;
    private final NameProtocol p;
    private final ChainView    chain;
    private final FrameStore   store;
    private NameMachine machine;
    private volatile int term;
    /** 心跳快照：每次落盘后更新，读取不取节点锁。 */
    private volatile Heartbeat snapshot;
    /** opHash → seq，用于幂等。不属于确定性状态，由日志重建。 */
    private final Map<String, Long> opIndex = new HashMap<>();

    public NameNode(NodeConfig cfg) {
        MlDsa87.selfCheck();
        this.cfg = cfg;
        this.p = cfg.protocol();
        this.chain = cfg.chain();
        this.store = new FrameStore(cfg.dataDir());
        rebuild();
    }

    /** 从日志重放出全部状态。启动、清空重同步时调用。 */
    private void rebuild() {
        machine = new NameMachine(p, cfg.instanceId());
        opIndex.clear();
        int t = 0;
        for (long s = 1; s <= store.maxSeq(); s++) {
            NameFrame f = store.frame(s);
            machine.apply(f);
            opIndex.put(f.op().opHash(), f.seq);
            t = Math.max(t, f.term);
        }
        term = Math.max(term, t);
        refresh();
    }

    private void refresh() {
        snapshot = new Heartbeat(cfg.nodeId(), term, store.maxSeq(), machine.execHash(),
                cfg.nodeId().equals(cfg.order().get(term % cfg.order().size())));
    }

    // ── 角色 ──────────────────────────────────────────────────────

    public String  nodeId()    { return cfg.nodeId(); }
    public int term() { return term; }
    public String primaryId() { return cfg.order().get(term % cfg.order().size()); }
    public boolean isPrimary() { return nodeId().equals(primaryId()); }

    // ── 写入（客户端入口）─────────────────────────────────────────

    /** POST /v1/register、/v1/unregister。非主节点透传给主节点。 */
    public SubmitResult submit(byte[] opBytes, byte[] signature) {
        if (!isPrimary()) return cfg.transport().forwardSubmit(primaryId(), opBytes, signature);
        synchronized (this) {
            if (!isPrimary()) return cfg.transport().forwardSubmit(primaryId(), opBytes, signature);
            return submitAsPrimary(opBytes, signature);
        }
    }

    private SubmitResult submitAsPrimary(byte[] opBytes, byte[] sig) {
        NameOp op;
        try {
            op = NameOp.fromBytes(opBytes);
        } catch (RuntimeException e) {
            return SubmitResult.dropped(-1, "请求格式错误: " + e.getMessage());
        }
        if (!op.userSigned()) return SubmitResult.dropped(-1, "客户端不能提交系统操作");
        if (!op.chain.equals(p.chain)) return SubmitResult.dropped(-1, "chain 不符: " + op.chain);
        long now = cfg.wallClock().getAsLong();
        if (Math.abs(op.timestamp - now) > p.entranceClockSkewMs)
            return SubmitResult.dropped(-1, "时间戳超出 ±" + p.entranceClockSkewMs + "ms 窗口");

        Long seen = opIndex.get(op.opHash());
        if (seen != null) return resultOf(store.frame(seen), "重复请求，返回原结果");

        try {
            byte[] pk = chain.pubkeyOf(op.address);
            if (pk == null) return SubmitResult.dropped(-1, "链上查不到地址公钥: " + op.address);
            if (!MlDsa87.verify(pk, op.signBytes(), sig)) return SubmitResult.dropped(-1, "签名无效");

            long ct = Math.max(machine.lastChainTime(), chain.chainTime());
            PledgeFact pf = (op instanceof RegisterOp r)
                    ? chain.authPledge(op.address, p.pledgeTag, r.credentialHash) : PledgeFact.none();
            FrameInput in = input(op, pf, ct);
            int code = machine.evaluate(in);

            if (op instanceof RegisterOp && (code == ResultCode.NAME_TAKEN || code == ResultCode.ADDRESS_HAS_NAME)) {
                String victim = code == ResultCode.NAME_TAKEN ? op.name
                        : machine.state().holderName(op.tag(), op.address);
                if (tryExpire(victim, ct)) {
                    in = input(op, pf, ct);
                    code = machine.evaluate(in);
                }
            }
            if (!machine.loggable(op, code))
                return SubmitResult.dropped(code, p.resultCodes.get(code));
            return commit(in, code, sig);
        } catch (ChainUnavailableException e) {
            return SubmitResult.unavailable("公链不可达: " + e.getMessage());
        }
    }

    /** 原持有者的授权质押已不存在 → 写 expire 帧回收。返回是否回收成功。 */
    private boolean tryExpire(String name, long ct) {
        if (name == null) return false;
        NameRecord rec = machine.state().record(name);
        if (rec == null) return false;
        PledgeFact hp = chain.authPledge(rec.address(), p.pledgeTag, rec.credentialHash());
        if (hp.exists()) return false;
        ExpireOp e = new ExpireOp(p.chain, rec.address(), name, ct, rec.credentialHash());
        FrameInput ein = FrameInput.noPledge(e, ct, store.maxSeq() + 1);
        int code = machine.evaluate(ein);
        if (code != ResultCode.OK) return false;
        commit(ein, code, new byte[0]);
        return true;
    }

    private FrameInput input(NameOp op, PledgeFact pf, long ct) {
        return new FrameInput(op, pf.exists(), pf.exists() ? pf.assetId() : "", pf.exists() ? pf.amount() : 0L,
                ct, store.maxSeq() + 1);
    }

    private SubmitResult commit(FrameInput in, int code, byte[] sig) {
        byte[] sigHash = sig.length == 0 ? Sha3.zero32() : Sha3.hash(sig);
        NameFrame f = NameFrame.build(term, in, code, sigHash, machine.execHash());
        FramePacket pkt = new FramePacket(f, sig);
        machine.apply(f);
        try {
            store.append(pkt);
        } catch (RuntimeException e) {
            rebuild();   // 内存状态已推进而落盘失败：按日志重建，保持"日志是权威"
            throw e;
        }
        opIndex.put(in.op().opHash(), f.seq);
        refresh();
        int acks = replicate(pkt);
        if (acks < p.minBackupAcks)
            return new SubmitResult(SubmitResult.Status.PENDING, code, f.seq,
                    "备份确认 " + acks + "/" + p.minBackupAcks);
        return resultOf(f, "");
    }

    private int replicate(FramePacket pkt) {
        int acks = 0;
        for (String id : cfg.order()) {
            if (id.equals(nodeId())) continue;
            Ack a = cfg.transport().pushFrame(nodeId(), id, pkt);
            if (a != null && a.seq() == pkt.frame().seq && Sha3.equalsConstantTime(a.execHash(), pkt.frame().execHash))
                acks++;
        }
        return acks;
    }

    private SubmitResult resultOf(NameFrame f, String msg) {
        return new SubmitResult(f.result == ResultCode.OK ? SubmitResult.Status.OK : SubmitResult.Status.REJECTED,
                f.result, f.seq, f.result == ResultCode.OK ? msg : (p.resultCodes.get(f.result) + (msg.isEmpty() ? "" : "；" + msg)));
    }

    // ── 收帧（备节点）─────────────────────────────────────────────

    public synchronized Ack onFrame(String from, FramePacket pkt) {
        NameFrame f = pkt.frame();
        if (f.term < term) return null;                       // 旧任期的帧：拒收（隔离旧主）
        if (f.term > term) { term = f.term; refresh(); }       // 采纳更高的 term；若本节点是旧主，自动退位
        if (f.seq <= store.maxSeq()) return ackIfSame(f);
        if (f.seq > store.maxSeq() + 1) {
            catchUp(from);
            if (f.seq <= store.maxSeq()) return ackIfSame(f);
            if (f.seq > store.maxSeq() + 1) return null;
        }
        return accept(pkt) ? new Ack(nodeId(), term, f.seq, f.execHash) : null;
    }

    private Ack ackIfSame(NameFrame f) {
        NameFrame mine = store.frame(f.seq);
        if (mine != null && Sha3.equalsConstantTime(mine.execHash, f.execHash))
            return new Ack(nodeId(), term, f.seq, f.execHash);
        System.err.println("[" + nodeId() + "] ⚠ seq=" + f.seq + " 与本地帧不一致，拒绝确认");
        return null;
    }

    /** 校验并接收一帧。失败返回 false，本地状态不变。 */
    private boolean accept(FramePacket pkt) {
        NameFrame f = pkt.frame();
        try {
            if (!signatureOk(pkt)) {
                System.err.println("[" + nodeId() + "] ⚠ seq=" + f.seq + " 签名校验失败");
                return false;
            }
            machine.apply(f);
        } catch (ChainUnavailableException e) {
            return false;                                      // 暂时无法验签，稍后追平时重试
        } catch (IllegalStateException e) {
            System.err.println("[" + nodeId() + "] ⚠ 拒收 seq=" + f.seq + "：" + e.getMessage());
            return false;
        }
        store.append(pkt);
        opIndex.put(f.op().opHash(), f.seq);
        term = Math.max(term, f.term);
        refresh();
        return true;
    }

    private boolean signatureOk(FramePacket pkt) {
        NameFrame f = pkt.frame();
        NameOp op = f.op();
        byte[] sig = pkt.signature();
        if (!op.userSigned()) return sig.length == 0 && Sha3.equalsConstantTime(f.sigHash, Sha3.zero32());
        if (sig.length == 0 || !Sha3.equalsConstantTime(Sha3.hash(sig), f.sigHash)) return false;
        byte[] pk = chain.pubkeyOf(op.address);
        return pk != null && MlDsa87.verify(pk, op.signBytes(), sig);
    }

    // ── 同步 ──────────────────────────────────────────────────────

    /** GET /v1/sync/pull?from= —— 只对节点开放。 */
    public List<FramePacket> pull(long fromSeq, int max) { return store.range(fromSeq, max); }

    /** 从 peer 拉取并追平。返回是否追到 peer 的末尾。 */
    public synchronized boolean catchUp(String peer) {
        while (true) {
            List<FramePacket> batch = cfg.transport().pull(peer, store.maxSeq() + 1, 256);
            if (batch == null) return false;
            if (batch.isEmpty()) return true;
            for (FramePacket pkt : batch) {
                if (pkt.frame().seq != store.maxSeq() + 1) return false;
                if (!accept(pkt)) return false;
            }
        }
    }

    public Heartbeat heartbeat() { return snapshot; }

    // ── 接班 ──────────────────────────────────────────────────────

    /** 手动接班（P1）。order[newTerm mod N] 必须是本节点。 */
    public synchronized void promote(int newTerm) {
        if (newTerm <= term) throw new IllegalStateException("newTerm 必须大于当前 term " + term);
        String who = cfg.order().get(newTerm % cfg.order().size());
        if (!who.equals(nodeId())) throw new IllegalStateException("term " + newTerm + " 的主节点是 " + who + "，不是本节点");
        term = newTerm;
        refresh();
    }

    /** 旧主恢复：清空本地数据，从 peer 全量重新同步，不抢回主位。 */
    public synchronized boolean rejoinFrom(String peer) {
        store.wipe();
        term = 0;
        rebuild();
        Heartbeat h = cfg.transport().heartbeat(peer);
        boolean ok = catchUp(peer);
        if (h != null) term = Math.max(term, h.term());
        refresh();
        return ok;
    }

    // ── 验证（POST /v1/verify）────────────────────────────────────

    public synchronized VerifyResult verify(String name, String address) {
        NameRecord rec = machine.state().record(name);
        if (rec == null)
            return new VerifyResult(VerifyResult.Status.NOT_FOUND, name, address, 0, "", store.maxSeq(), term, nodeId(), null, null);
        FramePacket ev = store.packet(rec.regSeq());
        VerifyResult.Status st = rec.address().equals(address) ? VerifyResult.Status.MATCH : VerifyResult.Status.MISMATCH;
        return new VerifyResult(st, name, rec.address(), rec.regSeq(), rec.credentialHash(), store.maxSeq(), term, nodeId(),
                ev.frame().opBytes, ev.signature());
    }

    // ── 只读 ──────────────────────────────────────────────────────

    public synchronized NameMachine machine() { return machine; }
    public synchronized long maxSeq()        { return store.maxSeq(); }
    public synchronized String execHex()     { return machine.execHex(); }
    public synchronized String stateDigest() { return machine.state().digest(); }

    @Override
    public synchronized void close() { store.close(); }
}
