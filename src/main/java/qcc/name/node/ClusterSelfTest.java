package qcc.name.node;

import qcc.name.Check;
import qcc.name.chain.MockChainView;
import qcc.name.codec.Sha3;
import qcc.name.crypto.MlDsa87;
import qcc.name.crypto.QccAddress;
import qcc.name.op.RegisterOp;
import qcc.name.protocol.NameProtocol;
import qcc.name.protocol.ProtocolLoader;
import qcc.name.store.FrameStore;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * P2P 集群自测（进程内，可控时钟）：
 *   创世 → 3 个核心经 seed 加入（其中 1 个经非主节点 seed）→ 2 个冗余加入
 *   → 写入（4 核心需 2 个 ACK）→ 主节点宕机 → 自动选举 → 旧主恢复：退位 + 分叉帧自动清空重同步
 *   → seeds 不可达不自封为主 → 重启沿用 cluster.json → 2 核心不自动接班
 */
public final class ClusterSelfTest {

    private final Check c = new Check();
    private final MockChainView chain = new MockChainView(1_793_520_000_000L);
    private final InMemoryTransport net = new InMemoryTransport();
    private NameProtocol p;
    private Path root;
    private final Map<String, NameNode> nodes = new LinkedHashMap<>();
    private int userNo;

    public static int run(String[] a) throws Exception { return new ClusterSelfTest().go(); }

    public static void main(String[] a) throws Exception { if (run(a) != 0) System.exit(1); }

    static final String A = "QGenesisAaaaaaaaaaaaaaaaaaaaaaaaaa", B = "QCoreBbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            C = "QCoreCcccccccccccccccccccccccccccc", D = "QCoreDddddddddddddddddddddddddddddd",
            O1 = "QObsvEeeeeeeeeeeeeeeeeeeeeeeeeeeee", O2 = "QObsvFfffffffffffffffffffffffffffff";

    private int go() throws Exception {
        root = Files.createTempDirectory("qccname-cluster");
        p = ProtocolLoader.loadFile(Path.of("testdata/qcc-name-test-v1.0.0.json"), null);
        try {
            step("1. 创世 + 加入");
            start(A, true, List.of());
            c.ck(n(A).isPrimary() && n(A).cores().equals(List.of(A)), "创世节点 A（seeds 为空）即主节点");
            start(B, true, List.of("mem://" + A));
            start(C, true, List.of("mem://" + A));
            start(D, true, List.of("mem://" + B));                        // 经非主节点 seed 加入
            start(O1, false, List.of("mem://" + C));
            start(O2, false, List.of("mem://" + A));
            tickAll();
            c.ck(n(A).cores().equals(List.of(A, B, C, D)), "核心按加入顺序 " + short4(n(A).cores()));
            c.ck(n(A).observers().containsAll(List.of(O1, O2)), "冗余节点 O1、O2 已登记");
            boolean same = true;
            for (NameNode x : nodes.values()) same &= x.clusterTable().get("ver").equals(n(A).clusterTable().get("ver")) && A.equals(x.primaryId());
            c.ck(same, "全部 6 个节点成员表一致，主=A");
            c.ck(n(D).joined() && !n(D).isPrimary(), "D 经非主节点 B 加入成功");

            step("2. 写入（4 核心 → 需要 2 个 ACK）");
            for (int i = 0; i < 4; i++) c.ck(reg(n(List.of(A, B, O1, D).get(i)), "p2p" + i + ".qcc").status() == SubmitResult.Status.OK, "经各节点注册 p2p" + i + ".qcc → OK");
            tickAll();
            c.ck(allSame(), "6 个节点 execHash 一致 seq=" + n(A).maxSeq());

            step("3. 主节点 A 宕机 → 自动选举");
            net.setDown(A, true);
            SubmitResult u = reg(n(B), "down.qcc");
            c.ck(u.status() == SubmitResult.Status.UNAVAILABLE, "A 宕机：写入暂不可用 → " + u.status());
            tickExcept(A);                                               // 各节点 hello A 失败
            chain.advance(31_000);
            tickExcept(A);                                               // B 顺位 1：发起选举
            c.ck(n(B).isPrimary() && n(B).term() == 1, "B 当选主节点 term=" + n(B).term());
            tickExcept(A);
            c.ck(B.equals(n(C).primaryId()) && B.equals(n(D).primaryId()) && B.equals(n(O1).primaryId()), "C、D、O1 采纳新主 B");
            SubmitResult w = reg(n(C), "after.qcc");
            c.ck(w.status() == SubmitResult.Status.OK, "经 C 写入（透传新主 B，C/D 确认 2 个 ACK）→ " + w.status());

            step("4. 旧主 A 恢复（不知道已被接班）");
            Thread.sleep(300);                                           // 等 B 对离线 A 的后台试推结束（失败）
            net.setDown(A, false);
            SubmitResult stray = reg(n(A), "stray.qcc");
            c.ck(stray.status() == SubmitResult.Status.PENDING, "直连旧主 A 写入：其他核心拒收旧 term → PENDING");
            n(B).syncTick();                                             // 新主广播
            c.ck(!n(A).isPrimary() && B.equals(n(A).primaryId()), "A 收到 announce 后自动退位");
            n(A).syncTick();                                             // hello → 发现分叉 → 自动重同步
            c.ck(n(A).execHex().equals(n(B).execHex()) && n(A).maxSeq() == n(B).maxSeq(), "A 的未确认分叉帧已丢弃，与 B 一致");
            tickAll();
            c.ck(allSame(), "全部节点一致 seq=" + n(B).maxSeq());

            step("5. 边界");
            NodeConfig lost = new NodeConfig("QLostGggggggggggggggggggggggggggggg", root.resolve("lost"), List.of(), List.of(), p,
                    "qccname-p2p", chain, net, chain::now, List.of("mem://QNobodyHhhhhhhhhhhhhhhhhhhhhhhhhhh"), null, true);
            NameNode ln = new NameNode(lost);
            net.register(ln);
            c.ck(!ln.join() && !ln.isPrimary() && !ln.joined(), "seeds 不可达：不加入、不自封为主");
            ln.close();
            nodes.get(C).close();
            NameNode c2 = start(C, true, List.of("mem://" + A));
            c.ck(c2.joined() && B.equals(c2.primaryId()) && c2.term() == 1, "C 重启：沿用 cluster.json（主=B，term=1）");
            c.ck(c.throwsAny(() -> new NameNode(new NodeConfig("QObsGenesisJjjjjjjjjjjjjjjjjjjjjjj", root.resolve("og"), List.of(), List.of(), p,
                    "qccname-p2p", chain, net, chain::now, List.of(), null, false))), "冗余节点不能当创世节点");

            step("6. 2 个核心：不自动接班");
            InMemoryTransport net2 = new InMemoryTransport();
            NameNode x = mk(net2, "QTwoXaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", List.of(), true);
            NameNode y = mk(net2, "QTwoYbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", List.of("mem://QTwoXaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), true);
            x.syncTick(); y.syncTick();
            net2.setDown(x.nodeId(), true);
            y.syncTick();
            chain.advance(120_000);
            y.syncTick();
            c.ck(!y.isPrimary(), "主节点失联 120s，y 不自动接班（防脑裂），需手动 promote");
            y.promote(y.term() + 1);
            c.ck(y.isPrimary(), "手动 promote 后 y 为主");
            x.close(); y.close();
        } finally {
            for (NameNode x : nodes.values()) x.close();
            FrameStore.deleteTree(root);
        }
        return c.failed();
    }

    private NameNode start(String id, boolean core, List<String> seeds) {
        NameNode x = mk(net, id, seeds, core);
        nodes.put(id, x);
        if (!x.joined()) x.join();
        return x;
    }

    private NameNode mk(InMemoryTransport t, String id, List<String> seeds, boolean core) {
        NameNode x = new NameNode(new NodeConfig(id, root.resolve(id), List.of(), List.of(), p, "qccname-p2p",
                chain, t, chain::now, seeds, null, core));
        t.register(x);
        return x;
    }

    private NameNode n(String id) { return nodes.get(id); }

    private void tickAll() { for (int i = 0; i < 2; i++) for (NameNode x : nodes.values()) x.syncTick(); }

    private void tickExcept(String id) { for (var e : nodes.entrySet()) if (!e.getKey().equals(id)) e.getValue().syncTick(); }

    private boolean allSame() {
        String e = null;
        for (NameNode x : nodes.values()) { if (e == null) e = x.execHex(); else if (!e.equals(x.execHex())) return false; }
        return true;
    }

    private SubmitResult reg(NameNode via, String name) {
        MlDsa87.Keys kp = MlDsa87.generate();
        String addr = QccAddress.derive(kp.pub());
        chain.putPubkey(addr, kp.pub());
        String cred = Sha3.toHex(Sha3.hashUtf8(addr + name));
        chain.lock(addr, p.pledgeTag, cred, "QCC", 1_000_000_000L, "QFrom");
        chain.advance(1);
        RegisterOp op = new RegisterOp(p.chain, addr, name, chain.now(), cred);
        return via.submit(op.toBytes(), MlDsa87.sign(kp.priv(), op.signBytes()));
    }

    private static String short4(List<String> ids) { return ids.stream().map(s -> s.substring(0, 6)).toList().toString(); }
    private static void step(String s) { System.out.println("\n── " + s + " " + "─".repeat(Math.max(4, 60 - s.length()))); }
}
