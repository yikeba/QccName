package qcc.name.sim;

import qcc.name.Check;
import qcc.name.chain.MockChainView;
import qcc.name.core.ResultCode;
import qcc.name.crypto.MlDsa87;
import qcc.name.crypto.QccAddress;
import qcc.name.node.*;
import qcc.name.op.NameOp;
import qcc.name.op.RegisterOp;
import qcc.name.op.UnregisterOp;
import qcc.name.protocol.NameProtocol;
import qcc.name.protocol.ProtocolLoader;
import qcc.name.store.FrameStore;
import qcc.name.verify.Replayer;
import qcc.name.verify.ResultVerifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;

/**
 * 本地模拟：两个 namespace 节点（name0 主 / name1 备）+ 模拟公链，
 * 跑通注册、删除、同步、接班的完整流程。所有签名都是真实的 ML-DSA-87。
 *
 * 运行（工程根目录，JDK 24+）：
 *   java -Dstdout.encoding=UTF-8 -cp build/classes/java/main qcc.name.sim.LocalSimulation [数据目录]
 * 数据目录默认为临时目录；指定目录时每次运行前会清空。
 */
public final class LocalSimulation {

    static final long QCC = 1_000_000_000L;
    static final long DAY = 86_400_000L;
    /** 模拟的协议发布者（= 链上协议交易的 from）。 */
    static final String PUBLISHER = "QWasmDyBQzCTdUhj6NLyfAzU6z5sTSdhM1";

    // ── 模拟用户 ──────────────────────────────────────────────────
    static final class User {
        final String label, address;
        final MlDsa87.Keys kp;
        User(String label, String address, MlDsa87.Keys kp) { this.label = label; this.address = address; this.kp = kp; }
    }

    private final Check c = new Check();
    private final MockChainView chain = new MockChainView(1_793_520_000_000L);
    private final InMemoryTransport net = new InMemoryTransport();
    private final SecureRandom rnd = new SecureRandom();
    private NameProtocol p;
    private Path root;
    private NameNode n0, n1;
    private final List<String> order = List.of("name0", "name1");

    public static int run(String[] args) throws Exception { return new LocalSimulation().go(args); }

    public static void main(String[] args) throws Exception { if (run(args) != 0) System.exit(1); }

    private int go(String[] args) throws Exception {
        root = args.length > 0 ? Path.of(args[0]) : Files.createTempDirectory("qccname-sim");
        FrameStore.deleteTree(root);
        Files.createDirectories(root);
        p = ProtocolLoader.loadFile(Path.of("testdata/qcc-name-test-v1.0.0.json"), null).withReservedPublisher(PUBLISHER);
        say("协议 " + p + "  （本地调试，未上链）");
        say("数据目录 " + root + "  签名实现 " + MlDsa87.source());

        n0 = node("name0");
        n1 = node("name1");

        User alice = user("alice"), bob = user("bob"), carol = user("carol"), dave = user("dave"),
             erin = user("erin"), frank = user("frank"), grace = user("grace");
        String ha = pledge(alice, QCC), hb = pledge(bob, QCC), hc = pledge(carol, QCC / 2),
               hd = pledge(dave, QCC), he = pledge(erin, QCC), hf = pledge(frank, QCC), hg = pledge(grace, QCC);

        step("1. 注册与规则");
        RegisterOp aliceReg = reg(alice, "alice.qcc", ha);
        expect(submit(n0, alice, aliceReg), SubmitResult.Status.OK, ResultCode.OK, "alice 注册 alice.qcc");
        c.ck(n1.maxSeq() == 1 && n1.execHex().equals(n0.execHex()), "备节点已同步 seq=1，execHash 一致");
        expect(submit(n0, bob, reg(bob, "alice.qcc", hb)), SubmitResult.Status.REJECTED, ResultCode.NAME_TAKEN, "bob 抢注 alice.qcc（拒绝也写入日志）");
        expect(submit(n0, bob, reg(bob, "a1ice.qcc", hb)), SubmitResult.Status.REJECTED, ResultCode.CONFUSABLE, "bob 注册形近名 a1ice.qcc");
        {   // Reserved：发布者在链上发布第 1 版（admin.qcc → dave），主节点写 reserve 帧，备节点同步
            String tx = "b1".repeat(32);
            byte[] doc = ("{\n  \"protocol\": \"qcc-name-reserved\",\n  \"version\": \"1.0.0\",\n  \"nameProtocolHash\": \"" + p.protocolHash
                    + "\",\n  \"seq\": 1,\n  \"prevTx\": \"\",\n  \"names\": {\"admin.qcc\": \"" + dave.address + "\"},\n  \"release\": []\n}\n")
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8);
            chain.putTx(new qcc.name.chain.ChainTx("b0".repeat(32), p.chain, bob.address, "QCCData", 499, chain.now(), doc));
            SubmitResult bad = n0.submitReserve(chain.tx("b0".repeat(32)));
            show("bob（非发布者）发布 Reserved", bad);
            c.ck(bad.status() == SubmitResult.Status.DROPPED && bad.resultCode() == ResultCode.RESERVE_PUBLISHER, "非发布者 → 入口丢弃（50）");
            chain.putTx(new qcc.name.chain.ChainTx(tx, p.chain, PUBLISHER, "QCCData", 500, chain.now(), doc));
            SubmitResult rs = n0.submitReserve(chain.tx(tx));
            show("发布者的 Reserved 第 1 版", rs);
            c.ck(rs.status() == SubmitResult.Status.OK, "Reserved 第 1 版生效（admin.qcc → dave）");
            c.ck(n1.execHex().equals(n0.execHex()) && n1.reservedApplied(tx), "备节点同步 reserve 帧，execHash 一致");
            c.ck(n0.submitReserve(chain.tx(tx)).status() == SubmitResult.Status.OK && n0.maxSeq() == n1.maxSeq(), "重复提交同一版：幂等");
            expect(submit(n0, bob, reg(bob, "admin.qcc", hb)), SubmitResult.Status.REJECTED, ResultCode.RESERVED, "bob 注册保留名 admin.qcc");
            VerifyResult rv = n1.verify("admin.qcc", dave.address);
            c.ck(rv.match() && rv.reserved() && tx.equals(rv.reservedTx()), "verify(admin.qcc, dave) @name1 → MATCH（按 Reserved 表）");
            c.ck(!n1.verify("admin.qcc", bob.address).match(), "verify(admin.qcc, bob) → MISMATCH");
            c.ck(n1.namesOf(dave.address).names().stream().anyMatch(h -> h.reserved() && h.name().equals("admin.qcc")), "反查 dave → 含保留名 admin.qcc");
        }
        long before = n0.maxSeq();
        expect(submit(n0, carol, reg(carol, "carol.qcc", hc)), SubmitResult.Status.DROPPED, ResultCode.PLEDGE_NOT_MET, "carol 只质押 0.5 QCC");
        c.ck(n0.maxSeq() == before, "质押不满足：入口丢弃，不进日志");
        expect(submit(n1, bob, reg(bob, "bob.qcc", hb)), SubmitResult.Status.OK, ResultCode.OK, "bob 向备节点 name1 提交 bob.qcc（透传主节点）");
        expect(submit(n0, alice, aliceReg), SubmitResult.Status.OK, ResultCode.OK, "alice 重发同一请求（幂等，返回原结果）");
        c.ck(n0.machine().state().nameCount() == 2, "当前名称数 = 2");

        RegisterOp forged = reg(bob, "bobby.osn", hb);
        SubmitResult fr = n0.submit(forged.toBytes(), MlDsa87.sign(carol.kp.priv(), forged.signBytes()));
        show("carol 冒充 bob 签名", fr);
        c.ck(fr.status() == SubmitResult.Status.DROPPED, "冒签 → 入口丢弃");
        RegisterOp stale = new RegisterOp(p.chain, bob.address, "bobby.osn", chain.now() - 10 * 60_000L, hb);
        expect(submit(n0, bob, stale), SubmitResult.Status.DROPPED, -1, "10 分钟前的请求（超出 ±5 分钟窗口）");

        step("2. 验证（L1：结果附带证据，任何人可对照公链核对）");
        VerifyResult v = n1.verify("alice.qcc", alice.address);
        say("verify(alice.qcc, alice) @name1 → " + v.status() + " regSeq=" + v.regSeq() + " asOf=" + v.asOfSeq());
        c.ck(v.match(), "备节点验证 MATCH");
        ResultVerifier.Report rep = ResultVerifier.check(v, p, chain);
        rep.lines().forEach(l -> say("    " + l));
        c.ck(rep.ok(), "L1 证据独立核对通过");
        c.ck(n0.verify("alice.qcc", bob.address).status() == VerifyResult.Status.MISMATCH, "verify(alice.qcc, bob) → MISMATCH");
        c.ck(n0.verify("nobody.qcc", bob.address).status() == VerifyResult.Status.NOT_FOUND, "verify(nobody.qcc) → NOT_FOUND");

        step("3. 备节点离线 → 追平");
        net.setDown("name1", true);
        expect(submit(n0, dave, reg(dave, "dave.qcc", hd)), SubmitResult.Status.PENDING, ResultCode.OK, "name1 离线时 dave 注册（主节点已落盘，确认不足）");
        net.setDown("name1", false);
        c.ck(n1.maxSeq() < n0.maxSeq(), "name1 恢复在线，落后 " + (n0.maxSeq() - n1.maxSeq()) + " 帧");
        n0.syncTick();
        say("主节点心跳（announce，每 10 秒）联系上 name1，解除暂停");
        expect(submit(n0, erin, reg(erin, "erin.qcc", he)), SubmitResult.Status.OK, ResultCode.OK, "erin 注册：推送时 name1 发现缺口，自动拉取补齐");
        c.ck(n1.maxSeq() == n0.maxSeq() && n1.execHex().equals(n0.execHex()), "name1 追平，execHash 一致");
        expect(submit(n0, dave, reg(dave, "dave.qcc", hd)), SubmitResult.Status.REJECTED, ResultCode.NAME_TAKEN,
                "dave 以新请求再注册 dave.qcc → 已是他的（证明 PENDING 那条已生效）");

        step("4. 删除与冷却期");
        long aliceSeq = n0.verify("alice.qcc", alice.address).regSeq();
        UnregisterOp wrongSeq = new UnregisterOp(p.chain, alice.address, "alice.qcc", tick(), aliceSeq + 1);
        expect(submit(n0, alice, wrongSeq), SubmitResult.Status.DROPPED, ResultCode.REGSEQ_MISMATCH, "alice 删除时 regSeq 写错");
        UnregisterOp byBob = new UnregisterOp(p.chain, bob.address, "alice.qcc", tick(), aliceSeq);
        expect(submit(n0, bob, byBob), SubmitResult.Status.DROPPED, ResultCode.HOLDER_MISMATCH, "bob 试图删除 alice.qcc");
        UnregisterOp un = new UnregisterOp(p.chain, alice.address, "alice.qcc", tick(), aliceSeq);
        expect(submit(n0, alice, un), SubmitResult.Status.OK, ResultCode.OK, "alice 删除 alice.qcc");
        expect(submit(n0, frank, reg(frank, "alice.qcc", hf)), SubmitResult.Status.REJECTED, ResultCode.COOLDOWN, "frank 冷却期内注册 alice.qcc");
        expect(submit(n0, alice, reg(alice, "alice.qcc", ha)), SubmitResult.Status.REJECTED, ResultCode.COOLDOWN, "alice 本人冷却期内重注册");
        expect(submit(n0, alice, reg(alice, "anna.qcc", ha)), SubmitResult.Status.OK, ResultCode.OK, "alice 删除后立即注册别的名字 anna.qcc");
        chain.advance(30 * DAY + 1);
        say("…… 链时间推进 30 天");
        expect(submit(n0, frank, reg(frank, "alice.qcc", hf)), SubmitResult.Status.OK, ResultCode.OK, "冷却期过后 frank 注册 alice.qcc");

        step("5. 质押撤销 → 惰性回收（expire）");
        chain.revoke(frank.address, p.pledgeTag, hf);
        say("frank 的授权方在链上撤销了质押");
        VerifyResult rv = n1.verify("alice.qcc", frank.address);
        c.ck(!rv.match() && rv.status() == VerifyResult.Status.REVOKED, "撤销后 verify → match=false（status=REVOKED，节点记录尚未回收）");
        c.ck(!ResultVerifier.check(rv, p, chain).ok(), "L1 独立核对同样不通过");
        long s0 = n0.maxSeq();
        expect(submit(n0, grace, reg(grace, "alice.qcc", hg)), SubmitResult.Status.REJECTED, ResultCode.COOLDOWN,
                "grace 注册 alice.qcc（撞上 frank 的失效名称）");
        c.ck(n0.maxSeq() == s0 + 2, "写入了 2 帧：先 expire 回收，回收后名称同样进入冷却期，注册被拒");
        c.ck(n1.verify("alice.qcc", frank.address).status() == VerifyResult.Status.NOT_FOUND, "两节点上 alice.qcc 已回收");
        chain.advance(30 * DAY + 1);
        say("…… 链时间再推进 30 天");
        expect(submit(n0, grace, reg(grace, "alice.qcc", hg)), SubmitResult.Status.OK, ResultCode.OK, "grace 再次注册 alice.qcc");
        c.ck(n0.verify("alice.qcc", grace.address).match() && n1.verify("alice.qcc", grace.address).match(), "两节点上 alice.qcc → grace");

        step("6. 主节点宕机 → 手动接班 → 旧主隔离与恢复");
        net.setDown("name0", true);
        SubmitResult un0 = submit(n1, bob, reg(bob, "bob.osn", hb));
        show("name0 宕机，向 name1 提交（透传失败）", un0);
        c.ck(un0.status() == SubmitResult.Status.UNAVAILABLE, "主节点不可达 → UNAVAILABLE");
        n1.promote(1);
        say("name1.promote(1)：手动接班（2 个核心不自动选举），name1 成为主节点");
        expect(submit(n1, bob, reg(bob, "bob.osn", hb)), SubmitResult.Status.PENDING, ResultCode.OK, "name1 作为新主受理 bob.osn（name0 仍离线）");

        Thread.sleep(300);                                              // 等 name1 对离线 name0 的后台试推结束（失败）
        net.setDown("name0", false);
        say("name0 网络恢复，但它还不知道已被接班（仍认为 term=0、自己是主）");
        RegisterOp strayOp = reg(dave, "dave.osn", hd);
        SubmitResult stray = n0.submit(strayOp.toBytes(), sign(dave, strayOp));
        show("客户端直连旧主 name0 提交 dave.osn", stray);
        c.ck(stray.status() == SubmitResult.Status.PENDING, "旧主落盘了一帧，但 name1（term=1）拒收 → 永远拿不到确认");
        c.ck(n1.verify("dave.osn", dave.address).status() == VerifyResult.Status.NOT_FOUND, "新主上没有 dave.osn：旧主的写入被隔离");

        n0.close();
        n0 = node("name0");
        say("name0 进程重启，执行 rejoinFrom(name1)：清空本地数据，全量重新同步");
        c.ck(n0.rejoinFrom("name1"), "全量同步完成");
        c.ck(n0.term() == 1 && !n0.isPrimary() && n0.execHex().equals(n1.execHex()), "name0 成为备节点，term=1，execHash 与新主一致");
        c.ck(n0.verify("dave.osn", dave.address).status() == VerifyResult.Status.NOT_FOUND, "旧主那条未确认的帧已被丢弃");
        n1.syncTick();
        say("新主 name1 心跳（announce）联系上 name0，解除暂停");
        expect(submit(n0, dave, reg(dave, "dave.osn", hd)), SubmitResult.Status.OK, ResultCode.OK, "dave 重新提交（经 name0 透传到新主 name1）");

        step("7. 重启重放与离线核对");
        String exec = n1.execHex(), digest = n1.stateDigest();
        n1.close();
        n1 = node("name1");
        c.ck(n1.execHex().equals(exec) && n1.stateDigest().equals(digest) && n1.isPrimary(), "name1 重启：从日志重放，execHash/状态/角色一致");
        n0.close();
        Replayer.Result rr0 = Replayer.replay(root.resolve("name0"), p, "qccname-local", chain);
        n0 = node("name0");
        Replayer.Result rr1;
        n1.close();
        rr1 = Replayer.replay(root.resolve("name1"), p, "qccname-local", chain);
        n1 = node("name1");
        say("离线重放 name0: " + rr0.frames() + " 帧，验签 " + rr0.sigChecked() + "，exec=" + rr0.execHash().substring(0, 16) + "…");
        say("离线重放 name1: " + rr1.frames() + " 帧，验签 " + rr1.sigChecked() + "，exec=" + rr1.execHash().substring(0, 16) + "…");
        c.ck(rr0.execHash().equals(rr1.execHash()) && rr0.stateDigest().equals(rr1.stateDigest()), "两份日志独立重放结果一致");

        step("结果");
        say("name0 " + n0.heartbeat().seq() + " 帧  term=" + n0.term() + "  exec=" + n0.execHex());
        say("name1 " + n1.heartbeat().seq() + " 帧  term=" + n1.term() + "  exec=" + n1.execHex());
        say("名称数 " + n1.machine().state().nameCount());
        n0.close();
        n1.close();
        if (args.length == 0) FrameStore.deleteTree(root);
        return c.failed();
    }

    // ── 工具 ──────────────────────────────────────────────────────

    private NameNode node(String id) {
        NameNode n = new NameNode(new NodeConfig(id, root.resolve(id), order, p, "qccname-local", chain, net, chain::now));
        net.register(n);
        return n;
    }

    private User user(String label) {
        MlDsa87.Keys kp = MlDsa87.generate();
        User u = new User(label, QccAddress.derive(kp.pub()), kp);     // 真实地址：由公钥推导
        chain.putPubkey(u.address, kp.pub());
        return u;
    }

    /** 在模拟链上为用户建一笔授权质押，返回授权交易 hash（credentialHash）。 */
    private String pledge(User u, long amount) {
        byte[] h = new byte[32];
        rnd.nextBytes(h);
        String hash = qcc.name.codec.Sha3.toHex(h);
        chain.lock(u.address, p.pledgeTag, hash, "QCC", amount, "QFromAssetWallet" + u.label);
        return hash;
    }

    private long tick() { chain.advance(1); return chain.now(); }

    private RegisterOp reg(User u, String name, String cred) { return new RegisterOp(p.chain, u.address, name, tick(), cred); }

    private byte[] sign(User u, NameOp op) { return MlDsa87.sign(u.kp.priv(), op.signBytes()); }

    private SubmitResult submit(NameNode n, User u, NameOp op) {
        return n.submit(op.toBytes(), sign(u, op));
    }

    private void expect(SubmitResult r, SubmitResult.Status st, int code, String what) {
        show(what, r);
        c.ck(r.status() == st && (code < 0 || r.resultCode() == code),
                "期望 " + st + (code >= 0 ? "(" + code + ")" : ""));
    }

    private static void show(String what, SubmitResult r) { System.out.println("  · " + what + " → " + r); }
    private static void step(String s) { System.out.println("\n── " + s + " " + "─".repeat(Math.max(4, 60 - s.length()))); }
    private static void say(String s)  { System.out.println("  " + s); }
}
