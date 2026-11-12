package qcc.name.node;

import qcc.name.chain.ChainUnavailableException;
import qcc.name.chain.ChainView;
import qcc.name.chain.PledgeFact;
import qcc.name.codec.Sha3;
import qcc.name.core.FrameInput;
import qcc.name.core.NameMachine;
import qcc.name.core.NameRecord;
import qcc.name.core.NameState;
import qcc.name.core.ResultCode;
import qcc.name.crypto.MlDsa87;
import qcc.name.frame.Ack;
import qcc.name.frame.FramePacket;
import qcc.name.frame.Heartbeat;
import qcc.name.frame.NameFrame;
import qcc.name.op.ExpireOp;
import qcc.name.op.ReserveOp;
import qcc.name.chain.ChainTx;
import qcc.name.op.NameOp;
import qcc.name.op.RegisterOp;
import qcc.name.protocol.NameProtocol;
import qcc.name.store.FrameStore;

import qcc.name.crypto.QccAddress;
import qcc.name.http.Json;
import qcc.name.store.PubkeyVault;
import qcc.name.protocol.StrictJson;
import qcc.name.protocol.TagPolicy;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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
 *      ACK ≥ min(minBackupAcks, 节点数-1) 才算生效；不足返回 PENDING（帧已在主节点日志中，备节点追平后生效）
 *      单节点运行时不要求备份确认（启动日志会提示"无备份"）
 *
 * ═══ 收帧（备节点）════════════════════════════════════════════════
 *   term 低于本地 → 拒收（旧主的帧）；seq 有缺口 → 先向发送方拉取补齐；
 *   验签（链上公钥）→ 核心 apply（结果码与 execHash 必须一致）→ 落盘 → ACK
 *
 * ═══ 集群（P2P）════════════════════════════════════════════════════
 *   成员表见 Cluster：创世节点（seeds 为空）即主节点；其他节点连任意 seed 取得成员表后，向主节点 hello 加入。
 *   公网 IPv4 → 核心节点（参与确认、投票、接班）；只有 IPv6 / NAT → 冗余节点（只同步与查询）。
 *   主节点每 10 秒向全体成员 announce（成员表 + 进度）；其他节点每 10 秒向主节点 hello（上报地址、追平、分叉检测）。
 *
 * ═══ 确认数 ═════════════════════════════════════════════════════
 *   核心 ≥3：ACK ≥ 过半数-1（加上主节点自己即过半）—— 少数派里的旧主永远拿不到确认，选举后不会分叉
 *   核心 <3：ACK ≥ min(minBackupAcks, 核心数-1)
 *
 * ═══ 接班 ═══════════════════════════════════════════════════════
 *   核心 ≥3 自动：主节点失联 30 秒（按接班顺位每位再加 10 秒）→ 发起选举，过半核心投票即接任。
 *     投票条件：投票方自己也已 15 秒联系不上主节点、本任期未投过票、候选人日志不落后（lastTerm, seq）。
 *   核心 <3 手动：/admin/promote（两节点之间断网时双方都会认为对方宕机，自动接班会形成两个主）。
 *   旧主恢复：收到更高 term → 自动退位；hello 发现本地有未确认的分叉帧 → 自动清空并全量重新同步。
 *
 * 线程模型：解析、验签、查质押在节点锁之外并行；状态检查与写帧在锁内串行。
 * pull / heartbeat 不取节点锁（主节点推帧时持锁，备节点发现缺口会反向拉取）。
 * 日志是权威，状态由重放得出。
 */
public final class NameNode implements AutoCloseable {

    private final NodeConfig   cfg;
    private final NameProtocol p;
    private final ChainView    chain;
    private final FrameStore   store;
    private NameMachine machine;
    /** 集群成员表（term、主节点、成员）。读写均在节点锁内。 */
    private final Cluster cl;
    /** 链上没有公钥的地址（0 资产签名钱包）的公钥快照。 */
    private final PubkeyVault keys;
    /** 日志中最后一帧的 term（选举比较日志新旧用）。 */
    private int logTerm;
    /** 最近一次与主节点联系成功的时间（wallClock）。 */
    private volatile long lastPrimaryContact;
    /** 心跳快照：每次落盘后更新，读取不取节点锁。 */
    private volatile Heartbeat snapshot;
    /** opHash → seq，用于幂等。不属于确定性状态，由日志重建。 */
    private final Map<String, Long> opIndex = new ConcurrentHashMap<>();
    /** 后台：推送冗余节点、广播成员表。单线程保证顺序，不阻塞写入。 */
    private final ExecutorService bg = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "qccname-bg");
        t.setDaemon(true);
        return t;
    });

    static final long FAIL_MS = 30_000;         // 主节点失联多久发起选举
    static final long RANK_MS = 10_000;         // 每个接班顺位额外等待
    static final long VOTE_SILENT_MS = 15_000;  // 投票方自己至少这么久联系不上主节点才投票

    public NameNode(NodeConfig cfg) {
        MlDsa87.selfCheck();
        this.cfg = cfg;
        this.p = cfg.protocol();
        this.chain = cfg.chain();
        this.store = new FrameStore(cfg.dataDir());
        this.cl = new Cluster(cfg.dataDir().resolve("cluster.json"));
        this.keys = new PubkeyVault(cfg.dataDir().resolve("pubkeys"));
        boolean had = cl.loadFile();
        rebuild();
        if (!had) initCluster();
        cl.term = Math.max(cl.term, logTerm);
        Cluster.Addr me = cfg.selfAddr().get();
        if (me != null && isPrimary() && !me.equals(cl.addrs.get(nodeId()))) { cl.addrs.put(nodeId(), me); cl.ver++; }
        if (cl.joined()) cl.save();
        lastPrimaryContact = now();
        cfg.transport().updatePeers(cl.urls());
        refresh();
    }

    private void initCluster() {
        if (!cfg.order().isEmpty()) {                            // 静态成员表（测试）
            cl.cores.addAll(cfg.order());
            cl.observers.addAll(cfg.observers());
            cl.primary = cfg.order().getFirst();
        } else if (cfg.seeds().isEmpty()) {                      // 创世节点
            if (store.maxSeq() > 0)
                throw new IllegalStateException("本地已有 " + store.maxSeq() + " 帧但没有 cluster.json，且未配置 seeds —— 无法确定集群；请配置 seeds 重新加入");
            if (!cfg.selfCore())
                throw new IllegalStateException("创世节点（seeds 为空）必须是核心节点：需要公网 IPv4，或配置 advertiseIp / role=core");
            cl.cores.add(nodeId());
            cl.primary = nodeId();
            System.out.println("[cluster] 创世节点：本机为主节点 term=0");
        }                                                        // 否则：等待通过 seeds 加入
        Cluster.Addr me = cfg.selfAddr().get();
        if (me != null) cl.addrs.put(nodeId(), me);
        cl.ver = 1;
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
        logTerm = t;
        refresh();
    }

    private void refresh() {
        if (cl == null) return;
        snapshot = new Heartbeat(cfg.nodeId(), cl.term, store.maxSeq(), machine.execHash(), isPrimary());
    }

    private long now() { return cfg.wallClock().getAsLong(); }

    // ── 角色 ──────────────────────────────────────────────────────

    public String  nodeId()    { return cfg.nodeId(); }
    public synchronized int term()         { return cl.term; }
    public synchronized String primaryId() { return cl.primary; }
    public synchronized boolean isPrimary() { return nodeId().equals(cl.primary); }
    public synchronized boolean joined()    { return cl.joined(); }
    public synchronized boolean isCore()    { return cl.isCore(nodeId()); }
    public synchronized List<String> cores()     { return List.copyOf(cl.cores); }
    public synchronized List<String> observers() { return List.copyOf(cl.observers); }
    public synchronized String clusterInfo()     { return cl.toString(); }
    public synchronized Map<String, Object> clusterTable() { return cl.toMap(); }

    // ── 写入（客户端入口）─────────────────────────────────────────

    /** POST /v1/register、/v1/unregister（不带公钥）。 */
    public SubmitResult submit(byte[] opBytes, byte[] signature) { return submit(opBytes, signature, new byte[0]); }

    /**
     * POST /v1/register、/v1/unregister。非主节点透传给主节点。
     * pubkey 可为空：链上或本地快照已有该地址公钥时不需要；0 资产钱包首次操作时必须提供。
     */
    public SubmitResult submit(byte[] opBytes, byte[] signature, byte[] pubkey) {
        if (pubkey == null) pubkey = new byte[0];
        String pid = primaryId();
        if (pid == null) return SubmitResult.unavailable("本节点尚未加入集群");
        if (!pid.equals(nodeId())) return cfg.transport().forwardSubmit(pid, opBytes, signature, pubkey);
        Pre pre = precheck(opBytes, signature, pubkey);                 // 锁外：解析、入口检查、验签、查质押
        if (pre.result() != null) {
            SubmitResult r = pre.result();
            if (r.status() == SubmitResult.Status.DROPPED || r.status() == SubmitResult.Status.UNAVAILABLE) {
                winDrop.incrementAndGet();
                System.out.println("[丢弃] " + (pre.op() == null ? "（无法解析）" : opLabel(pre.op())) + " → " + r.status() + "：" + r.message());
            }
            return r;
        }
        synchronized (this) {                                   // 锁内：状态检查、回收、写帧
            if (!isPrimary()) return cfg.transport().forwardSubmit(cl.primary, opBytes, signature, pubkey);
            Long seen = opIndex.get(pre.op().opHash());
            if (seen != null) return resultOf(store.frame(seen), "重复请求，返回原结果");
            try {
                return decide(pre.op(), pre.pledge(), signature, pre.carryKey(), pre.cacheKey());
            } catch (ChainUnavailableException e) {
                return SubmitResult.unavailable("公链不可达: " + e.getMessage());
            }
        }
    }

    /** carryKey：要随帧携带的公钥（链上没有该地址公钥时），否则空数组。 */
    private record Pre(NameOp op, PledgeFact pledge, SubmitResult result, byte[] carryKey, boolean cacheKey) {
        Pre(NameOp op, PledgeFact pledge, SubmitResult result) { this(op, pledge, result, new byte[0], false); }
    }

    /** 地址公钥的来源。 */
    public record KeyInfo(byte[] pubkey, String source) {}

    /**
     * 查地址公钥：本地快照 → 链上。快照里的公钥都已校验过"推导出该地址"，与链上的必然相同，先查快照省一次链查询。
     * 都没有返回 null；链不可达抛 ChainUnavailableException。
     */
    public KeyInfo pubkeyOf(String address) {
        byte[] k = keys.get(address);
        if (k != null) return new KeyInfo(k, "cache");
        k = chain.pubkeyOf(address);
        return k == null ? null : new KeyInfo(k, "chain");
    }

    private Pre precheck(byte[] opBytes, byte[] sig, byte[] submittedKey) {
        NameOp op;
        try {
            op = NameOp.fromBytes(opBytes);
        } catch (RuntimeException e) {
            return new Pre(null, null, SubmitResult.dropped(-1, "请求格式错误: " + e.getMessage()));
        }
        if (!op.userSigned()) return new Pre(op, null, SubmitResult.dropped(-1, "客户端不能提交系统操作"));
        if (!op.chain.equals(p.chain)) return new Pre(op, null, SubmitResult.dropped(-1, "chain 不符: " + op.chain));
        long now = cfg.wallClock().getAsLong();
        if (Math.abs(op.timestamp - now) > p.entranceClockSkewMs)
            return new Pre(op, null, SubmitResult.dropped(-1, "时间戳超出 ±" + p.entranceClockSkewMs + "ms 窗口"));
        Long seen = opIndex.get(op.opHash());
        if (seen != null) return new Pre(op, null, resultOf(store.frame(seen), "重复请求，返回原结果"));
        try {
            // 公钥：快照 → 链上 → 请求中提交的（必须推导出该地址）。
            // 用户签名的帧一律携带公钥：各链节点的公钥库并不总是一致（有的节点有、有的没有），
            // 帧自带公钥后，任何节点、任何第三方都能只凭帧本身验签，不受各自链视图影响。
            byte[] pk, carry;
            boolean cacheKey = false;
            byte[] cached = keys.get(op.address);
            byte[] onChain = cached == null ? chain.pubkeyOf(op.address) : null;
            if (cached != null || onChain != null) {
                pk = cached != null ? cached : onChain;
                if (submittedKey.length > 0 && !java.util.Arrays.equals(submittedKey, pk))
                    return new Pre(op, null, SubmitResult.dropped(-1, "提交的公钥与该地址已知公钥不一致"));
                carry = pk;
            } else {
                if (submittedKey.length == 0)
                    return new Pre(op, null, SubmitResult.dropped(-1, "链上查不到地址公钥（0 资产钱包请随请求提交 pubkey）: " + op.address));
                if (!QccAddress.matches(submittedKey, op.address))
                    return new Pre(op, null, SubmitResult.dropped(-1, "公钥与地址不匹配（该公钥推导出的不是 " + op.address + "）"));
                pk = submittedKey;
                carry = submittedKey;
                cacheKey = true;                                 // 链上没有：本地快照保存
            }
            if (!MlDsa87.verify(pk, op.signBytes(), sig)) return new Pre(op, null, SubmitResult.dropped(-1, "签名无效"));
            PledgeFact pf = (op instanceof RegisterOp r)
                    ? chain.authPledge(op.address, p.pledgeTag, r.credentialHash) : PledgeFact.none();
            return new Pre(op, pf, null, carry, cacheKey);
        } catch (ChainUnavailableException e) {
            return new Pre(op, null, SubmitResult.unavailable("公链不可达: " + e.getMessage()));
        }
    }

    /** 已持有节点锁。 */
    private SubmitResult decide(NameOp op, PledgeFact pf, byte[] sig, byte[] carryKey, boolean cacheKey) {
        long ct = Math.max(machine.lastChainTime(), chain.chainTime());
        FrameInput in = input(op, pf, ct);
        int code = machine.evaluate(in);
        if (op instanceof RegisterOp && (code == ResultCode.NAME_TAKEN || code == ResultCode.ADDRESS_HAS_NAME)) {
            String victim = code == ResultCode.NAME_TAKEN ? op.name : machine.state().holderName(op.tag(), op.address);
            if (tryExpire(victim, ct)) {
                in = input(op, pf, ct);
                code = machine.evaluate(in);
            }
        }
        if (!machine.loggable(op, code)) {
            winDrop.incrementAndGet();
            System.out.println("[丢弃] " + opLabel(op) + " → DROPPED(" + code + ")：" + p.resultCodes.get(code));
            return SubmitResult.dropped(code, p.resultCodes.get(code));
        }
        return commit(in, code, sig, carryKey, cacheKey);
    }

    // ── Reserved（主节点，由 ReservedWatcher 调用）──────────────────────

    /** Reserved 文档交易是否已在日志中生效。 */
    public synchronized boolean reservedApplied(String txHash) { return machine.state().reservedApplied(txHash); }

    /**
     * 把一笔已由多个链节点确认的 Reserved 交易写成 reserve 帧。只有主节点执行；
     * 检查不通过（发布者 / seq / prevTx / 高度 / 文档）入口丢弃，不进日志，返回 DROPPED 与原因。
     */
    public SubmitResult submitReserve(ChainTx tx) {
        if (!p.reservedEnabled()) return SubmitResult.dropped(ResultCode.RESERVE_PUBLISHER, "Reserved 未启用（未配置 protocolTx）");
        if (!"QCCData".equals(tx.assetId()))
            return SubmitResult.dropped(ResultCode.RESERVE_DOCUMENT, "Reserved 必须是 QCCData 交易，实际 " + tx.assetId());
        ReserveOp op;
        try {
            op = new ReserveOp(tx.chain(), tx.from(), tx.confirmTimestamp(), tx.txHash(), tx.height(), tx.payload());
            op.validate();
        } catch (RuntimeException e) {
            return SubmitResult.dropped(ResultCode.RESERVE_DOCUMENT, "Reserved 交易结构不符: " + e.getMessage());
        }
        synchronized (this) {
            if (!isPrimary()) return SubmitResult.unavailable("本节点不是主节点");
            Long seen = opIndex.get(op.opHash());
            if (seen != null) return resultOf(store.frame(seen), "已生效");
            long ct = Math.max(machine.lastChainTime(), chain.chainTime());
            FrameInput in = FrameInput.noPledge(op, ct, store.maxSeq() + 1);
            int code = machine.evaluate(in);
            if (code != ResultCode.OK) {
                String why = code == ResultCode.RESERVE_DOCUMENT ? machine.documentProblem(op) : null;
                return SubmitResult.dropped(code, p.resultCodes.get(code) + (why == null ? "" : "：" + why));
            }
            return commit(in, code, new byte[0]);
        }
    }

    /** 原持有者的授权质押已不存在 → 写 expire 帧回收。返回是否回收成功。 */
    private boolean tryExpire(String name, long ct) {
        if (name == null) return false;
        NameRecord rec = machine.state().record(name);
        if (rec == null) return false;
        // 回收不可撤回：多链节点时需至少 2 个节点一致确认质押不存在（防止落后节点误判）
        if (!chain.pledgeGoneConfirmed(rec.address(), p.pledgeTag, rec.credentialHash())) return false;
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

    private SubmitResult commit(FrameInput in, int code, byte[] sig) { return commit(in, code, sig, new byte[0], false); }

    private SubmitResult commit(FrameInput in, int code, byte[] sig, byte[] carryKey, boolean cacheKey) {
        byte[] sigHash = sig.length == 0 ? Sha3.zero32() : Sha3.hash(sig);
        NameFrame f = NameFrame.build(cl.term, in, code, sigHash, machine.execHash());
        FramePacket pkt = new FramePacket(f, sig, carryKey);
        if (cacheKey && keys.put(f.op().address, carryKey, f.seq))   // 先入快照：公钥已绑定地址，多存不会错
            System.out.println("[公钥] 缓存 " + f.op().address + "（链上无公钥）");
        machine.apply(f);
        try {
            store.append(pkt);
        } catch (RuntimeException e) {
            rebuild();   // 内存状态已推进而落盘失败：按日志重建，保持"日志是权威"
            throw e;
        }
        opIndex.put(in.op().opHash(), f.seq);
        refresh();
        logTerm = f.term;
        long t0 = System.nanoTime();
        int acks = replicate(pkt);
        int need = needAcks();
        boolean pending = acks < need;
        winWrite.incrementAndGet();
        (pending ? winPending : code == ResultCode.OK ? winOk : winRej).incrementAndGet();
        if (logOps) System.out.println("[写入] seq=" + f.seq + " " + opLabel(in.op()) + " → "
                + (pending ? "PENDING" : code == ResultCode.OK ? "OK" : "拒绝") + "(" + code + ")"
                + "  确认 " + acks + "/" + need + "  " + (System.nanoTime() - t0) / 1_000_000 + "ms");
        if (pending)
            return new SubmitResult(SubmitResult.Status.PENDING, code, f.seq,
                    "备份确认 " + acks + "/" + need);
        return resultOf(f, "");
    }

    /** 推送失败的对端暂停 30 秒（期间由对端 syncTick 自行追平），避免每次写入都等连接超时。 */
    private final Map<String, Long> peerDownUntil = new ConcurrentHashMap<>();
    private static final long PEER_DOWN_MS = 30_000;

    private boolean peerDown(String id) { Long t = peerDownUntil.get(id); return t != null && t > System.currentTimeMillis(); }

    private Ack push(String id, FramePacket pkt) {
        Ack a = cfg.transport().pushFrame(nodeId(), id, pkt);
        if (a == null) peerDownUntil.put(id, System.currentTimeMillis() + PEER_DOWN_MS);
        else peerDownUntil.remove(id);
        return a;
    }

    /** 确认数：核心 ≥3 时要求过半（防分叉），否则 min(minBackupAcks, 核心数-1)。 */
    private int needAcks() {
        int n = cl.cores.size();
        if (n >= 3) return Math.max(p.minBackupAcks, cl.majority() - 1);
        return Math.min(p.minBackupAcks, Math.max(0, n - 1));
    }

    /**
     * 推送给核心节点并统计确认。暂停中的节点（30 秒内推送失败过）直接跳过，不再同步等待连接超时：
     * 它恢复后由主节点 announce（每 10 秒）清除暂停，并由它自己的 hello 追平缺的帧。
     */
    private int replicate(FramePacket pkt) {
        for (String id : cl.observers)                          // 冗余节点：异步推送，不计入确认
            if (!id.equals(nodeId())) bg.execute(() -> { if (!peerDown(id)) push(id, pkt); });
        int acks = 0;
        for (String id : List.copyOf(cl.cores)) {
            if (id.equals(nodeId())) continue;
            if (peerDown(id)) { probe(id, pkt); continue; }
            if (acked(push(id, pkt), pkt)) acks++;
        }
        return acks;
    }

    /** 暂停中的节点：后台试推一次（同一节点同时只有一个），成功即解除暂停，后续写入恢复确认。 */
    private final java.util.Set<String> probing = ConcurrentHashMap.newKeySet();

    private void probe(String id, FramePacket pkt) {
        if (!probing.add(id)) return;
        bg.execute(() -> {
            try { push(id, pkt); } finally { probing.remove(id); }
        });
    }

    private static boolean acked(Ack a, FramePacket pkt) {
        return a != null && a.seq() == pkt.frame().seq && Sha3.equalsConstantTime(a.execHash(), pkt.frame().execHash);
    }

    private SubmitResult resultOf(NameFrame f, String msg) {
        return new SubmitResult(f.result == ResultCode.OK ? SubmitResult.Status.OK : SubmitResult.Status.REJECTED,
                f.result, f.seq, f.result == ResultCode.OK ? msg : (p.resultCodes.get(f.result) + (msg.isEmpty() ? "" : "；" + msg)));
    }

    // ── 收帧（备节点）─────────────────────────────────────────────

    public synchronized Ack onFrame(String from, FramePacket pkt) {
        if (!cl.joined()) return null;
        NameFrame f = pkt.frame();
        if (f.term < cl.term) return null;                    // 旧任期的帧：拒收（隔离旧主）
        if (f.term > cl.term) {                               // 新任期：采纳；若本节点是旧主，自动退位
            boolean was = isPrimary();
            cl.term = f.term;
            if (from != null && cl.isCore(from)) cl.primary = from;
            cl.save();
            if (was && !isPrimary()) System.out.println("[cluster] 收到 term=" + f.term + " 的帧，本节点退位为备节点");
            refresh();
        }
        if (from != null && from.equals(cl.primary)) lastPrimaryContact = now();
        if (f.seq <= store.maxSeq()) return ackIfSame(f);
        if (f.seq > store.maxSeq() + 1) {
            catchUp(from == null || from.isEmpty() ? cl.primary : from);
            if (f.seq <= store.maxSeq()) return ackIfSame(f);
            if (f.seq > store.maxSeq() + 1) return null;
        }
        if (!accept(pkt)) return null;
        winRecv.incrementAndGet();
        if (logOps) System.out.println("[同步] seq=" + f.seq + " " + opLabel(f.op()) + " → " + (f.result == ResultCode.OK ? "OK" : "拒绝") + "(" + f.result + ")");
        return new Ack(nodeId(), cl.term, f.seq, f.execHash);
    }

    private Ack ackIfSame(NameFrame f) {
        NameFrame mine = store.frame(f.seq);
        if (mine != null && Sha3.equalsConstantTime(mine.execHash, f.execHash))
            return new Ack(nodeId(), cl.term, f.seq, f.execHash);
        System.err.println("[" + nodeId() + "] ⚠ seq=" + f.seq + " 与本地帧不一致，拒绝确认");
        return null;
    }

    /** 校验并接收一帧。失败返回 false，本地状态不变。 */
    private boolean accept(FramePacket pkt) {
        NameFrame f = pkt.frame();
        try {
            String bad = signatureProblem(pkt);
            if (bad != null) {
                System.err.println("[" + nodeId() + "] ⚠ seq=" + f.seq + " 签名校验失败：" + bad);
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
        logTerm = Math.max(logTerm, f.term);
        refresh();
        return true;
    }

    /** 校验帧中的用户签名。通过返回 null，否则返回具体原因（便于定位：签名包 / 公钥来源 / 验签后端）。 */
    private String signatureProblem(FramePacket pkt) {
        NameFrame f = pkt.frame();
        NameOp op = f.op();
        byte[] sig = pkt.signature();
        if (!op.userSigned())
            return sig.length == 0 && Sha3.equalsConstantTime(f.sigHash, Sha3.zero32()) ? null : "系统操作不应带签名";
        if (sig.length == 0) return "帧中缺少签名";
        if (!Sha3.equalsConstantTime(Sha3.hash(sig), f.sigHash)) return "签名与 sigHash 不符（签名包损坏，长度 " + sig.length + "）";
        byte[] pk;
        String src;
        if (pkt.pubkey().length > 0) {                          // 随帧携带的公钥：必须推导出该地址
            if (!QccAddress.matches(pkt.pubkey(), op.address))
                return "携带的公钥（" + pkt.pubkey().length + " 字节）推导出 " + QccAddress.derive(pkt.pubkey()) + "，不是 " + op.address;
            pk = pkt.pubkey();
            src = "帧携带";
        } else {
            KeyInfo k = pubkeyOf(op.address);
            if (k == null) return "帧未携带公钥，本地快照与链上都查不到 " + op.address + "（上游节点版本过旧？）";
            pk = k.pubkey();
            src = k.source();
        }
        if (!MlDsa87.verify(pk, op.signBytes(), sig))
            return "ML-DSA-87 验签不通过（公钥来源 " + src + "，公钥 " + pk.length + " 字节，签名 " + sig.length + " 字节，后端 " + MlDsa87.source() + "）";
        // 备 / 冗余节点也保存帧携带的公钥：接班后处理不带公钥的请求时不必依赖链上（各链节点公钥库并不一致）
        if (pkt.pubkey().length > 0) keys.put(op.address, pkt.pubkey(), f.seq);
        return null;
    }

    // ── 同步 ──────────────────────────────────────────────────────

    /** GET /v1/sync/pull?from= —— 只对节点开放。 */
    public List<FramePacket> pull(long fromSeq, int max) {
        List<FramePacket> raw = store.range(fromSeq, max), out = new ArrayList<>(raw.size());
        for (FramePacket pk : raw) out.add(withKey(pk));
        return out;
    }

    /** 旧帧未携带公钥时（升级前写入），补上本节点已知的公钥，接收方仍会校验它推导出该地址。 */
    private FramePacket withKey(FramePacket pkt) {
        NameOp op = pkt.frame().op();
        if (pkt.pubkey().length > 0 || !op.userSigned()) return pkt;
        try {
            KeyInfo k = pubkeyOf(op.address);
            return k == null ? pkt : new FramePacket(pkt.frame(), pkt.signature(), k.pubkey());
        } catch (RuntimeException e) {
            return pkt;
        }
    }

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

    // ── 集群消息（/internal/cluster）──────────────────────────────

    /** 处理集群消息，返回 JSON。 */
    public byte[] onCluster(byte[] json) {
        Map<String, Object> m = StrictJson.parseObject(json);
        Map<String, Object> r = switch (StrictJson.str(m, "t")) {
            case "hello"    -> onHello(m);
            case "ping"     -> { synchronized (this) { yield cl.toMap(); } }     // 只读：不登记对方（创世前探测用）
            case "announce" -> onAnnounce(m);
            case "vote"     -> onVote(m);
            default -> throw new IllegalArgumentException("未知集群消息");
        };
        return Json.write(r).getBytes(StandardCharsets.UTF_8);
    }

    /** 本节点自我介绍：id、地址、角色、当前 seq。 */
    private Map<String, Object> intro(String t) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("t", t);
        m.put("id", nodeId());
        Cluster.Addr a = cfg.selfAddr().get();
        m.put("addr", a == null ? "" : a.toString());
        m.put("core", cfg.selfCore());
        m.put("seq", maxSeq());
        return m;
    }

    /** hello：任何节点都回成员表与进度；主节点同时登记 / 更新对方。 */
    private synchronized Map<String, Object> onHello(Map<String, Object> m) {
        if (isPrimary()) admit(m);
        Map<String, Object> r = cl.toMap();
        r.put("seq", store.maxSeq());
        r.put("exec", Sha3.toHex(machine.execHash()));
        long at = StrictJson.num(m, "seq");                      // 主节点在对方 seq 处的 execHash —— 对方据此判断是否分叉
        if (at > 0 && at <= store.maxSeq()) r.put("execAt", Sha3.toHex(store.frame(at).execHash));
        return r;
    }

    /** 主节点登记成员（已持锁）。首次加入按自报角色；之后只更新地址。 */
    private void admit(Map<String, Object> m) {
        String id = StrictJson.str(m, "id");
        boolean changed = false;
        if (!cl.isMember(id)) {
            boolean core = StrictJson.bool(m, "core");
            (core ? cl.cores : cl.observers).add(id);
            System.out.println("[cluster] 新节点加入 " + (core ? "核心 " : "冗余 ") + id + " " + StrictJson.strAllowEmpty(m, "addr"));
            changed = true;
        }
        String a = StrictJson.strAllowEmpty(m, "addr");
        if (!a.isEmpty()) {
            Cluster.Addr ad = Cluster.parseAddr(a);
            if (!ad.equals(cl.addrs.get(id))) {
                if (cl.addrs.containsKey(id)) System.out.println("[cluster] " + Cluster.shortId(id) + " 地址变更 → " + ad);
                cl.addrs.put(id, ad);
                changed = true;
            }
        }
        if (changed) {
            cl.ver++;
            cl.save();
            cfg.transport().updatePeers(cl.urls());
            bg.execute(this::announceAll);
        }
    }

    /** announce：主节点广播的成员表。采纳更新的表并回报自己。 */
    private Map<String, Object> onAnnounce(Map<String, Object> m) {
        adopt(m, false);
        synchronized (this) {
            if (StrictJson.strAllowEmpty(m, "primary").equals(cl.primary)) lastPrimaryContact = now();
        }
        return intro("intro");
    }

    /** 采纳成员表：force=false 时只采纳比本地新的。 */
    private synchronized boolean adopt(Map<String, Object> m, boolean force) {
        if (!force && cl.joined() && !cl.olderThan(m)) return false;
        if (StrictJson.strAllowEmpty(m, "primary").isEmpty()) return false;
        boolean was = isPrimary();
        int keepVoted = cl.votedTerm;
        String keepFor = cl.votedFor;
        cl.load(m);
        cl.term = Math.max(cl.term, logTerm);
        cl.votedTerm = keepVoted;
        cl.votedFor = keepFor;
        cl.save();
        cfg.transport().updatePeers(cl.urls());
        refresh();
        if (was && !isPrimary()) System.out.println("[cluster] 新主节点 " + cl.primary + "（term=" + cl.term + "），本节点退位");
        return true;
    }

    /** vote：选举投票。 */
    private synchronized Map<String, Object> onVote(Map<String, Object> m) {
        int t = (int) StrictJson.num(m, "term");
        String cand = StrictJson.str(m, "candidate");
        long seq = StrictJson.num(m, "seq");
        int lt = (int) StrictJson.num(m, "lastTerm");
        String why = null;
        if (t <= cl.term) why = "term 不高于本地";
        else if (t <= cl.votedTerm) why = "本任期已投票";
        else if (!cl.isCore(cand) || !cl.isCore(nodeId())) why = "非核心节点";
        else if (isPrimary()) why = "本节点是主节点且在线";
        else if (now() - lastPrimaryContact < VOTE_SILENT_MS) why = "本节点仍能联系到主节点";
        else if (lt < logTerm || (lt == logTerm && seq < store.maxSeq())) why = "候选人日志落后";
        if (why == null) {
            cl.votedTerm = t;
            cl.votedFor = cand;
            cl.save();
            System.out.println("[cluster] 投票给 " + Cluster.shortId(cand) + " term=" + t);
        }
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("granted", why == null);
        r.put("term", cl.term);
        r.put("reason", why == null ? "" : why);
        return r;
    }

    private Map<String, Object> send(String target, Map<String, Object> msg) {
        byte[] r = cfg.transport().cluster(target, Json.write(msg).getBytes(StandardCharsets.UTF_8));
        if (r == null) return null;
        try { return StrictJson.parseObject(r); } catch (RuntimeException e) { return null; }
    }

    /** 主节点：向全体成员广播成员表，顺带收集对方地址。 */
    void announceAll() {
        Map<String, Object> msg;
        List<String> targets;
        synchronized (this) {
            if (!isPrimary()) return;
            msg = cl.toMap();
            msg.put("t", "announce");
            targets = cl.members();
        }
        for (String id : targets) {                              // 不跳过暂停中的节点：announce 正是发现它恢复的途径
            if (id.equals(nodeId())) continue;
            Map<String, Object> r = send(id, msg);
            if (r == null) { peerDownUntil.put(id, System.currentTimeMillis() + PEER_DOWN_MS); continue; }
            peerDownUntil.remove(id);
            synchronized (this) { if (isPrimary() && StrictJson.str(r, "id").equals(id)) admit(r); }
        }
    }

    // ── 进度日志 ──────────────────────────────────────────────────

    /** 每帧打印一行（[写入] / [同步]）。批量追平（catchUp）只打印汇总。 */
    public static volatile boolean logOps = true;
    private final java.util.concurrent.atomic.AtomicInteger winWrite = new java.util.concurrent.atomic.AtomicInteger(),
            winOk = new java.util.concurrent.atomic.AtomicInteger(), winRej = new java.util.concurrent.atomic.AtomicInteger(),
            winPending = new java.util.concurrent.atomic.AtomicInteger(), winRecv = new java.util.concurrent.atomic.AtomicInteger(),
            winDrop = new java.util.concurrent.atomic.AtomicInteger();
    private volatile long primarySeq = -1;
    private long lastProgressAt = System.currentTimeMillis();

    private static String opLabel(NameOp op) {
        if (op instanceof ReserveOp r)
            return "保留名表 seq=" + (r.doc() == null ? "?" : r.doc().seq) + " 高度 " + r.height + " tx " + r.reservedTx.substring(0, 12) + "…";
        String kind = op instanceof RegisterOp ? "注册" : op instanceof ExpireOp ? "回收" : "删除";
        return kind + " " + op.name + " " + (op.address.length() > 10 ? op.address.substring(0, 10) + "…" : op.address);
    }

    /** 进度汇总（NodeMain 每 60 秒打印）：调用后清零窗口计数。 */
    public String progressLine() {
        long now = System.currentTimeMillis(), sec = Math.max(1, (now - lastProgressAt) / 1000);
        lastProgressAt = now;
        int w = winWrite.getAndSet(0), ok = winOk.getAndSet(0), rej = winRej.getAndSet(0), pd = winPending.getAndSet(0), rv = winRecv.getAndSet(0), dr = winDrop.getAndSet(0);
        long seq = maxSeq();
        String exec = execHex().substring(0, 12);
        synchronized (this) {
            if (!cl.joined()) return "[进度] 尚未加入集群，正在联系 seeds " + cfg.seeds();
            if (isPrimary()) {
                int online = 0, total = 0;
                for (String id : cl.members()) {
                    if (id.equals(nodeId())) continue;
                    total++;
                    if (!peerDown(id)) online++;
                }
                return "[进度] 主 term=" + cl.term + " seq=" + seq + " exec=" + exec + "…  近 " + sec + "s 写入 " + w
                        + "（OK " + ok + " / 拒绝 " + rej + " / PENDING " + pd + "）  入口丢弃 " + dr + "  成员在线 " + online + "/" + total
                        + "  核心 " + cl.cores.size() + " 冗余 " + cl.observers.size();
            }
            String role = cl.isCore(nodeId()) ? "备" : "冗余";
            long lag = primarySeq < 0 ? -1 : Math.max(0, primarySeq - seq);
            long silent = (now() - lastPrimaryContact) / 1000;
            return "[进度] " + role + " term=" + cl.term + " seq=" + seq + " exec=" + exec + "…  主 " + Cluster.shortId(cl.primary)
                    + " seq=" + (primarySeq < 0 ? "?" : primarySeq) + "  落后 " + (lag < 0 ? "?" : lag) + " 帧"
                    + "  近 " + sec + "s 收帧 " + rv + (silent > 15 ? "  ⚠ 主节点已 " + silent + "s 无响应" : "");
        }
    }

    // ── 定时任务（NodeMain 每 10 秒调用）─────────────────────────────

    /**
     * 主节点：更新自身地址、广播成员表。
     * 其他节点：未加入则联系 seeds；已加入则 hello 主节点 —— 上报地址、追平、分叉检测；主节点失联则视情况发起选举。
     */
    public void syncTick() {
        if (!joined()) { join(); return; }
        if (isPrimary()) {
            synchronized (this) {
                Cluster.Addr me = cfg.selfAddr().get();
                if (me != null && !me.equals(cl.addrs.get(nodeId()))) {
                    cl.addrs.put(nodeId(), me);
                    cl.ver++;
                    cl.save();
                    System.out.println("[cluster] 本机地址变更 → " + me);
                }
            }
            announceAll();
            return;
        }
        String pid = primaryId();
        long mySeq = maxSeq();
        Map<String, Object> intro = intro("hello");
        intro.put("seq", mySeq);
        Map<String, Object> r = send(pid, intro);
        if (r == null) { maybeElect(); return; }
        lastPrimaryContact = now();
        adopt(r, false);
        if (!pid.equals(primaryId())) return;                    // 主节点变了，下一轮再同步
        long ps = StrictJson.num(r, "seq");
        primarySeq = ps;
        boolean diverged = mySeq > ps;
        if (!diverged && mySeq > 0 && r.containsKey("execAt")) {
            NameFrame mine;
            synchronized (this) { mine = store.frame(mySeq); }
            diverged = mine != null && !Sha3.toHex(mine.execHash).equals(StrictJson.str(r, "execAt"));
        }
        if (diverged) {
            System.err.println("[sync] ⚠ 本地日志与主节点分叉（本地 " + mySeq + " / 主 " + ps + "）—— 本地多出的是旧主未确认的帧，自动清空并全量重新同步");
            boolean ok = rejoinFrom(pid);
            System.out.println("[sync] 全量重新同步" + (ok ? "完成" : "未完成") + "，当前 " + maxSeq() + " 帧");
        } else if (ps > mySeq) {
            long t0 = System.currentTimeMillis();
            boolean ok = catchUp(pid);
            System.out.println("[同步] 落后 " + (ps - mySeq) + " 帧，批量追平 " + mySeq + " → " + maxSeq() + (ok ? " 完成" : " 未完成")
                    + "  " + (System.currentTimeMillis() - t0) + "ms");
        }
    }

    /**
     * 启动探测：本地成员表可能已过期（例如本机是宕机后恢复的旧主）。向其他成员 hello，采纳更新的表。
     * NodeMain 在开放 HTTP 之前调用，避免旧主在知道自己被接班之前受理写入。
     */
    public void probe() {
        List<String> others;
        synchronized (this) {
            if (!cl.joined()) return;
            others = cl.members();
            others.remove(nodeId());
        }
        for (String id : others) {
            Map<String, Object> r = send(id, intro("hello"));
            if (r != null && adopt(r, false)) System.out.println("[cluster] 启动探测：采纳更新的成员表 " + clusterInfo());
        }
    }

    /** 未加入集群：依次联系 seeds，采纳成员表后 hello 主节点完成登记。返回是否已加入。 */
    public boolean join() {
        for (String url : cfg.seeds()) {
            byte[] raw = cfg.transport().clusterAt(url, Json.write(intro("hello")).getBytes(StandardCharsets.UTF_8));
            if (raw == null) continue;
            Map<String, Object> r;
            try { r = StrictJson.parseObject(raw); } catch (RuntimeException e) { continue; }
            if (!adopt(r, true)) continue;
            System.out.println("[cluster] 经 seed " + url + " 取得成员表：" + clusterInfo());
            String pid = primaryId();
            if (!pid.equals(nodeId())) {
                Map<String, Object> h = send(pid, intro("hello"));     // 向主节点登记
                if (h != null) { adopt(h, false); lastPrimaryContact = now(); }
                catchUp(pid);
            }
            return true;
        }
        System.err.println("[cluster] seeds " + cfg.seeds() + " 均不可达，10 秒后重试（不会自封为主节点）");
        return false;
    }

    /** 主节点失联：核心 ≥3 时按接班顺位等待后发起选举。 */
    private void maybeElect() {
        int rank, n;
        synchronized (this) {
            if (!cl.isCore(nodeId())) return;
            n = cl.cores.size();
            rank = cl.rankAfterPrimary(nodeId());
        }
        long silent = now() - lastPrimaryContact;
        if (n < 3) {
            if (silent > FAIL_MS) System.err.println("[cluster] ⚠ 主节点失联 " + silent / 1000 + "s；核心节点 <3，不自动接班（需要时手动 /admin/promote）");
            return;
        }
        if (rank < 1 || silent < FAIL_MS + (rank - 1) * RANK_MS) return;
        elect();
    }

    /** 发起选举：过半核心节点（含自己）同意即接任主节点。 */
    public boolean elect() {
        int t;
        long seq;
        int lt;
        List<String> voters;
        synchronized (this) {
            t = Math.max(cl.term, cl.votedTerm) + 1;
            cl.votedTerm = t;
            cl.votedFor = nodeId();
            cl.save();
            seq = store.maxSeq();
            lt = logTerm;
            voters = new ArrayList<>(cl.cores);
            voters.remove(nodeId());
        }
        System.out.println("[cluster] 主节点失联，发起选举 term=" + t);
        Map<String, Object> req = new LinkedHashMap<>();
        req.put("t", "vote");
        req.put("term", t);
        req.put("candidate", nodeId());
        req.put("seq", seq);
        req.put("lastTerm", lt);
        int votes = 1;
        for (String v : voters) {
            Map<String, Object> r = send(v, req);
            if (r != null && StrictJson.bool(r, "granted")) votes++;
        }
        synchronized (this) {
            if (votes < cl.majority() || cl.term >= t) {
                System.out.println("[cluster] 选举 term=" + t + " 未成功（得票 " + votes + "/" + cl.cores.size() + "，需要 " + cl.majority() + "）");
                lastPrimaryContact = now();                     // 退避，下一轮再看
                return false;
            }
            cl.term = t;
            cl.primary = nodeId();
            cl.ver++;
            cl.save();
            refresh();
            System.out.println("[cluster] ✓ 当选主节点 term=" + t + "（得票 " + votes + "/" + cl.cores.size() + "）");
        }
        announceAll();
        return true;
    }

    // ── 手动运维 ──────────────────────────────────────────────────

    /** 手动接班：本节点必须是核心节点，newTerm 必须大于当前 term。 */
    public void promote(int newTerm) {
        synchronized (this) {
            if (newTerm <= cl.term) throw new IllegalStateException("newTerm 必须大于当前 term " + cl.term);
            if (!cl.isCore(nodeId())) throw new IllegalStateException("本节点不是核心节点，不能接班");
            cl.term = newTerm;
            cl.votedTerm = Math.max(cl.votedTerm, newTerm);
            cl.primary = nodeId();
            cl.ver++;
            cl.save();
            refresh();
        }
        bg.execute(this::announceAll);
    }

    /** 主节点：移除一个已下线的节点（否则它一直计入过半数）。 */
    public void removeMember(String id) {
        synchronized (this) {
            if (!isPrimary()) throw new IllegalStateException("只能在主节点上移除成员");
            if (id.equals(nodeId())) throw new IllegalStateException("不能移除主节点自己");
            if (!cl.cores.remove(id) && !cl.observers.remove(id)) throw new IllegalStateException("不是成员：" + id);
            cl.addrs.remove(id);
            cl.ver++;
            cl.save();
        }
        bg.execute(this::announceAll);
    }

    /** 清空本地数据，从 peer 全量重新同步，并采纳 peer 的成员表。 */
    public synchronized boolean rejoinFrom(String peer) {
        store.wipe();
        rebuild();
        boolean ok = catchUp(peer);
        Map<String, Object> r = send(peer, intro("hello"));
        if (r != null) adopt(r, true);
        lastPrimaryContact = now();
        refresh();
        return ok;
    }

    // ── 验证（POST /v1/verify）────────────────────────────────────

    /**
     * 验证名称与地址是否对应。地址匹配时再查一次链：注册所用的授权质押必须当前仍有效。
     * 链查询在节点锁之外进行，不阻塞写入。
     */
    public VerifyResult verify(String name, String address) {
        NameRecord rec;
        FramePacket ev;
        long asOf;
        int t;
        synchronized (this) {
            NameState st = machine.state();
            String ra = st.reservedAddress(name);
            if (ra != null) {                                    // 保留名：按 Reserved 表回答，优先于注册信息
                NameState.ReservedVersion cur = st.reservedCurrent();
                byte[] opb = store.frame(cur.logSeq()).opBytes;
                VerifyResult.Status s = ra.isEmpty() ? VerifyResult.Status.NOT_FOUND
                        : ra.equals(address) ? VerifyResult.Status.MATCH : VerifyResult.Status.MISMATCH;
                return new VerifyResult(s, name, ra, cur.logSeq(), "", store.maxSeq(), cl.term, nodeId(), opb, new byte[0],
                        null, true, cur.tx());
            }
            rec = st.record(name);
            asOf = store.maxSeq();
            t = cl.term;
            ev = rec == null ? null : store.packet(rec.regSeq());
        }
        if (rec == null)
            return new VerifyResult(VerifyResult.Status.NOT_FOUND, name, address, 0, "", asOf, t, nodeId(), null, null, null);
        VerifyResult.Status st;
        if (!rec.address().equals(address)) {
            st = VerifyResult.Status.MISMATCH;
        } else {
            try {
                st = chain.authPledge(rec.address(), p.pledgeTag, rec.credentialHash()).exists()
                        ? VerifyResult.Status.MATCH : VerifyResult.Status.REVOKED;
            } catch (ChainUnavailableException e) {
                st = VerifyResult.Status.UNVERIFIED;
            }
        }
        byte[] evKey = ev.pubkey().length > 0 ? ev.pubkey() : keys.get(rec.address());   // 链上没有公钥时随证据给出
        return new VerifyResult(st, name, rec.address(), rec.regSeq(), rec.credentialHash(), asOf, t, nodeId(),
                ev.frame().opBytes, ev.signature(), evKey);
    }

    // ── 按地址反查（GET /v1/address）──────────────────────────────

    /** 地址名下的一个名字。status 同 verify：MATCH / REVOKED / UNVERIFIED。 */
    public record HeldName(String name, VerifyResult.Status status, long regSeq, String credentialHash, long regTime,
                           boolean reserved, String reservedTx) {
        HeldName(String name, VerifyResult.Status status, long regSeq, String credentialHash, long regTime) {
            this(name, status, regSeq, credentialHash, regTime, false, "");
        }
    }

    public record AddressNames(String address, List<HeldName> names, long asOfSeq, int term, String nodeId) {}

    /**
     * 地址名下的全部名字（每个 tag 至多一个），每个名字都实时查链确认注册质押仍有效。
     * 链查询在节点锁之外进行。
     */
    public AddressNames namesOf(String address) {
        List<NameRecord> recs = new ArrayList<>();
        List<String> names = new ArrayList<>();
        List<HeldName> reservedNames = new ArrayList<>();
        long asOf;
        int t;
        synchronized (this) {
            NameState st = machine.state();
            NameState.ReservedVersion cur = st.reservedCurrent();
            for (Map.Entry<String, String> e : st.reservedTable().entrySet())     // 保留名：表中指向该地址的全部名字
                if (e.getValue().equals(address))
                    reservedNames.add(new HeldName(e.getKey(), VerifyResult.Status.MATCH, cur.logSeq(), "", cur.chainTime(), true, cur.tx()));
            for (String tag : p.tags.keySet()) {
                String n = st.holderName(tag, address);
                NameRecord r = n == null ? null : st.record(n);
                if (r != null && r.address().equals(address) && st.reservedAddress(n) == null) { names.add(n); recs.add(r); }
            }
            asOf = store.maxSeq();
            t = cl.term;
        }
        List<HeldName> out = new ArrayList<>(reservedNames);
        for (int i = 0; i < recs.size(); i++) {
            NameRecord r = recs.get(i);
            VerifyResult.Status s;
            try {
                s = chain.authPledge(address, p.pledgeTag, r.credentialHash()).exists()
                        ? VerifyResult.Status.MATCH : VerifyResult.Status.REVOKED;
            } catch (ChainUnavailableException e) {
                s = VerifyResult.Status.UNVERIFIED;
            }
            out.add(new HeldName(names.get(i), s, r.regSeq(), r.credentialHash(), r.regTime()));
        }
        return new AddressNames(address, out, asOf, t, nodeId());
    }

    /** 注册质押所在的链上 tag（qccio）：凭证三要素 = address + pledgeTag + credentialHash。 */
    public String pledgeTag() { return p.pledgeTag; }

    // ── 注册前预检（GET /v1/check）────────────────────────────────

    /** 预检结果：available = 现在提交注册预计会成功。 */
    public record CheckResult(boolean available, int resultCode, String reason, String holder) {}

    /**
     * 不写日志、不需要签名，按协议检查顺序预演一次注册，客户端可在签名前（手机上签名要数十秒）先确认名字能不能注册。
     *   address 可空：为空时跳过"地址已有名字"检查；时间戳检查始终跳过
     *   credentialHash 可空：为空时跳过质押检查（只查名字本身）
     * 预检只反映此刻的状态，不预留名字：提交时仍以主节点的实际结果为准。
     */
    public CheckResult check(String name, String address, String credentialHash) {
        name = name == null ? "" : name.trim().toLowerCase();
        int dot = name.indexOf('.');
        if (dot <= 0 || dot == name.length() - 1) return new CheckResult(false, ResultCode.LABEL_FORMAT, "名称应为 label.tag，如 alice.qcc", null);
        String tag = name.substring(dot + 1);
        TagPolicy t = p.tag(tag);
        if (t == null) return new CheckResult(false, ResultCode.TAG_NOT_OPEN, "命名空间 ." + tag + " 未开放", null);
        if (!t.open()) return new CheckResult(false, ResultCode.TAG_NOT_OPEN,
                "." + tag + " 是企业级 namespace，不开放注册，名字由发布者在 Reserved 中分配", null);
        boolean noAddr = address == null || address.isBlank();
        String addr = noAddr ? "QCheckOnlyAaaaaaaaaaaaaaaaaaaaaaaaa" : address.trim();
        boolean noCred = credentialHash == null || credentialHash.isBlank();
        String cred = noCred ? "0".repeat(64) : credentialHash.trim().toLowerCase();

        PledgeFact pf;
        if (noCred) {
            pf = new PledgeFact(true, t.assetId(), Long.MAX_VALUE, "");      // 跳过质押检查
        } else {
            try {
                pf = chain.authPledge(addr, p.pledgeTag, cred);
            } catch (ChainUnavailableException e) {
                return new CheckResult(false, -1, "公链暂不可达，无法确认质押", null);
            }
        }
        RegisterOp op;
        try {
            op = new RegisterOp(p.chain, addr, name, Long.MAX_VALUE / 2, cred);   // 时间戳取大值：预检不判时间戳
        } catch (RuntimeException e) {
            return new CheckResult(false, ResultCode.LABEL_FORMAT, "名称格式错误：" + e.getMessage(), null);
        }
        synchronized (this) {
            int code;
            try {
                code = machine.evaluate(input(op, pf, Math.max(machine.lastChainTime(), now())));
            } catch (RuntimeException e) {
                return new CheckResult(false, ResultCode.LABEL_FORMAT, "名称格式错误：" + e.getMessage(), null);
            }
            NameRecord rec = machine.state().record(name);
            String holder = rec == null ? null : rec.address();
            String reason = switch (code) {
                case ResultCode.OK -> "可以注册";
                case ResultCode.LABEL_FORMAT -> "格式不符：2–32 位 a-z 0-9 -，首尾不能是 -";
                case ResultCode.RESERVED -> "保留名（或与保留名形近），由协议发布者在 Reserved 中指定，不能注册";
                case ResultCode.CONFUSABLE -> "与已注册的名字形近（0/o、1/l、rn/m 视为相同）";
                case ResultCode.NAME_TAKEN -> "已被注册";
                case ResultCode.COOLDOWN -> "冷却期中（删除或回收后 30 天内任何人不能注册）";
                case ResultCode.TAG_NOT_OPEN -> "命名空间未开放";
                case ResultCode.ADDRESS_HAS_NAME -> "该地址在 ." + tag + " 下已有名字：" + machine.state().holderName(tag, addr);
                case ResultCode.TS_NOT_MONOTONIC -> "时间戳未递增";
                case ResultCode.PLEDGE_NOT_MET -> "授权质押不存在或不满足（tag=" + p.pledgeTag + "，≥ " + t.minAmount() + " " + t.assetId() + "）";
                default -> p.resultCodes.getOrDefault(code, String.valueOf(code));
            };
            if (code == ResultCode.NAME_TAKEN && holder != null) {   // 持有人质押已撤销：会被回收，但回收后进入冷却期
                try {
                    if (chain.pledgeGoneConfirmed(holder, p.pledgeTag, rec.credentialHash()))
                        reason = "已被注册（持有人质押已撤销，提交注册会先回收，但回收后进入 30 天冷却期）";
                } catch (RuntimeException ignored) { }
            }
            return new CheckResult(code == ResultCode.OK, code, noCred && code == ResultCode.OK ? reason + "（未检查质押）" : reason, holder);
        }
    }

    // ── 只读 ──────────────────────────────────────────────────────

    public synchronized NameMachine machine() { return machine; }
    public synchronized long maxSeq()        { return store.maxSeq(); }
    public synchronized String execHex()     { return machine.execHex(); }
    public synchronized String stateDigest() { return machine.state().digest(); }
    public NameProtocol protocol()           { return p; }

    /** 当前 Reserved 表与全部历史（GET /v1/reserved）。 */
    public record ReservedInfo(boolean enabled, String publisher, java.util.SortedMap<String, String> names,
                               List<NameState.ReservedVersion> history, long asOfSeq, int term, String nodeId) {}

    public synchronized ReservedInfo reservedInfo() {
        NameState st = machine.state();
        return new ReservedInfo(p.reservedEnabled(), p.reservedPublisher, new java.util.TreeMap<>(st.reservedTable()),
                st.reservedHistory(), store.maxSeq(), cl.term, nodeId());
    }

    @Override
    public synchronized void close() {
        bg.shutdownNow();
        store.close();
        keys.close();
    }
}
