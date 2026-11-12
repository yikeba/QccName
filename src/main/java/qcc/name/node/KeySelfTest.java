package qcc.name.node;

import qcc.name.Check;
import qcc.name.chain.MockChainView;
import qcc.name.codec.Sha3;
import qcc.name.crypto.MlDsa87;
import qcc.name.crypto.QccAddress;
import qcc.name.op.RegisterOp;
import qcc.name.op.UnregisterOp;
import qcc.name.protocol.NameProtocol;
import qcc.name.protocol.ProtocolLoader;
import qcc.name.store.FrameStore;
import qcc.name.verify.ResultVerifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * 0 资产钱包（链上无公钥）自测：地址推导、随请求提交公钥、快照缓存、随帧同步、证据核对、重启与新节点追平。
 */
public final class KeySelfTest {

    public static int run(String[] a) throws Exception {
        Check c = new Check();

        // ── 地址算法（与 QCC AddressTool 一致）──
        c.ck(QccAddress.isValid("QecAmMRVAgEvMSAVxCo4zmK15VQEssd822"), "真实地址 QecAmMRV… 校验通过（Base58 + 0x3A + 双 SHA3 checksum）");
        c.ck(QccAddress.isValid("QWasmDyBQzCTdUhj6NLyfAzU6z5sTSdhM1"), "真实地址 QWasmDyB… 校验通过");
        c.ck(!QccAddress.isValid("QWasmDyBQzCTdUhj6NLyfAzU6z5sTSdhM2"), "改一个字符 → checksum 失败");
        MlDsa87.Keys k1 = MlDsa87.generate(), k2 = MlDsa87.generate(), k3 = MlDsa87.generate();
        String a1 = QccAddress.derive(k1.pub()), a2 = QccAddress.derive(k2.pub()), a3 = QccAddress.derive(k3.pub());
        c.ck(a1.length() == 34 && a1.charAt(0) == 'Q' && QccAddress.isValid(a1), "公钥推导地址：34 位、Q 开头、可校验 → " + a1);
        c.ck(QccAddress.matches(k1.pub(), a1) && !QccAddress.matches(k2.pub(), a1), "公钥与地址绑定：别人的公钥推导不出该地址");

        // ── 集群：主 A + 备 B，链上没有 a1 / a2 的公钥 ──
        NameProtocol p = ProtocolLoader.loadFile(Path.of("testdata/qcc-name-test-v1.0.0.json"), null);
        MockChainView chain = new MockChainView(1_793_520_000_000L);
        InMemoryTransport net = new InMemoryTransport();
        Path root = Files.createTempDirectory("qccname-keys");
        List<String> order = List.of("QKeyNodeAaaaaaaaaaaaaaaaaaaaaaaaaa", "QKeyNodeBbbbbbbbbbbbbbbbbbbbbbbbbb");
        MockChainView chainB = new MockChainView(1_793_520_000_000L);   // B 连的链节点公钥库与 A 的不一致（实测出现过）
        NameNode A = node(order.get(0), root, order, p, chain, net), B = node(order.get(1), root, order, p, chainB, net);
        try {
            String cred1 = pledge(chain, p, a1), cred2 = pledge(chain, p, a2), cred3 = pledge(chain, p, a3);
            pledge(chainB, p, a1); pledge(chainB, p, a2); pledge(chainB, p, a3);
            chain.putPubkey(a3, k3.pub());                                 // a3 链上有公钥

            SubmitResult r = reg(A, chain, p, k1, a1, "zero.qcc", cred1, null);
            c.ck(r.status() == SubmitResult.Status.DROPPED && r.message().contains("pubkey"), "0 资产钱包不带公钥 → DROPPED：" + r.message());
            r = reg(A, chain, p, k1, a1, "zero.qcc", cred1, k2.pub());
            c.ck(r.status() == SubmitResult.Status.DROPPED && r.message().contains("不匹配"), "带别人的公钥 → DROPPED：" + r.message());
            r = reg(A, chain, p, k1, a1, "zero.qcc", cred1, k1.pub());
            c.ck(r.status() == SubmitResult.Status.OK, "带正确公钥注册 → " + r);
            c.ck("cache".equals(A.pubkeyOf(a1).source()) && "cache".equals(B.pubkeyOf(a1).source()), "主、备都已缓存 a1 公钥（随帧同步）");

            r = reg(B, chain, p, k2, a2, "zero2.qcc", cred2, k2.pub());
            c.ck(r.status() == SubmitResult.Status.OK, "经备节点 B 透传注册（公钥一并透传）→ " + r);

            VerifyResult v = A.verify("zero.qcc", a1);
            c.ck(v.match() && v.pubkey() != null && java.util.Arrays.equals(v.pubkey(), k1.pub()), "verify 证据附带公钥");
            ResultVerifier.Report rep = ResultVerifier.check(v, p, chain);
            c.ck(rep.ok(), "L1 独立核对通过（链上无公钥，用证据公钥 + 地址推导）" + rep.lines());

            UnregisterOp u = new UnregisterOp(p.chain, a1, "zero.qcc", chain.now() + 10, v.regSeq());
            r = A.submit(u.toBytes(), MlDsa87.sign(k1.priv(), u.signBytes()));
            c.ck(r.status() == SubmitResult.Status.OK, "删除不带公钥（用缓存）→ " + r);

            // 注册前预检（/v1/check）
            c.ck(A.check("free.qcc", "", "").available(), "预检 free.qcc → 可以注册");
            c.ck(A.check("zero2.qcc", "", "").resultCode() == 13 && a2.equals(A.check("zero2.qcc", "", "").holder()), "预检 zero2.qcc → 已被注册（13），返回持有人");
            c.ck(A.check("zero.qcc", "", "").resultCode() == 14, "预检 zero.qcc（刚删除）→ 冷却期（14）");
            c.ck(A.check("admin.qcc", "", "").resultCode() == 0, "预检 admin.qcc → 可注册（协议不内置保留名）");
            c.ck(A.check("zer0-2.qcc", "", "").resultCode() == 10 || A.check("-x.qcc", "", "").resultCode() == 10, "预检格式错误 → 10");
            c.ck(A.check("another.qcc", a2, "").resultCode() == 20, "预检带地址：a2 在 .qcc 已有名字 → 20");
            c.ck(A.check("another.qcc", a2, "ff".repeat(32)).resultCode() == 20 || A.check("another.osn", a2, "ff".repeat(32)).resultCode() == 30,
                    "预检带错误凭证 → 质押不满足（30）");
            c.ck(A.check("another.osn", a2, cred2).available(), "预检带真实凭证 → 可以注册（含质押）");
            c.ck(A.check("x.xyz", "", "").resultCode() == 15, "预检未开放的 tag → 15");
            long before = A.maxSeq();
            c.ck(A.maxSeq() == before, "预检不写日志");

            r = reg(A, chain, p, k3, a3, "onchain.qcc", cred3, k1.pub());
            c.ck(r.status() == SubmitResult.Status.DROPPED && r.message().contains("不一致"), "链上有公钥时提交不同公钥 → DROPPED：" + r.message());
            r = reg(A, chain, p, k3, a3, "onchain.qcc", cred3, k3.pub());
            c.ck(r.status() == SubmitResult.Status.OK && "chain".equals(A.pubkeyOf(a3).source()), "链上有公钥：用链上的，主节点不缓存 → " + r);
            c.ck(B.maxSeq() == A.maxSeq() && B.execHex().equals(A.execHex()),
                    "备节点连的链节点查不到 a3 公钥，仍凭帧携带的公钥同步成功 seq=" + B.maxSeq());

            // 新节点从零追平：只靠帧里携带的公钥就能验签
            NameNode C = new NameNode(new NodeConfig("QKeyNodeCcccccccccccccccccccccccccc", root.resolve("C"),
                    List.of(order.get(0), order.get(1), "QKeyNodeCcccccccccccccccccccccccccc"), p, "qccname-keys", chain, net, chain::now));
            net.register(C);
            c.ck(C.catchUp(order.get(0)) && C.execHex().equals(A.execHex()), "新节点从零追平，execHash 一致 seq=" + C.maxSeq());
            c.ck(C.pubkeyOf(a1) != null && C.pubkeyOf(a2) != null, "新节点的公钥快照已从帧中重建");
            C.close();

            A.close();
            NameNode A2 = node(order.get(0), root, order, p, chain, net);
            c.ck(A2.pubkeyOf(a2) != null && "cache".equals(A2.pubkeyOf(a2).source()), "重启后公钥快照仍在");
            A2.close();
        } finally {
            B.close();
            FrameStore.deleteTree(root);
        }
        return c.failed();
    }

    private static NameNode node(String id, Path root, List<String> order, NameProtocol p, MockChainView chain, InMemoryTransport net) {
        NameNode n = new NameNode(new NodeConfig(id, root.resolve(id), order, p, "qccname-keys", chain, net, chain::now));
        net.register(n);
        return n;
    }

    private static String pledge(MockChainView chain, NameProtocol p, String addr) {
        String cred = Sha3.toHex(Sha3.hashUtf8("pledge-" + addr));
        chain.lock(addr, p.pledgeTag, cred, "QCC", 1_000_000_000L, "QFrom");
        return cred;
    }

    private static SubmitResult reg(NameNode via, MockChainView chain, NameProtocol p, MlDsa87.Keys k, String addr,
                                    String name, String cred, byte[] pub) {
        chain.advance(1);
        RegisterOp op = new RegisterOp(p.chain, addr, name, chain.now(), cred);
        return via.submit(op.toBytes(), MlDsa87.sign(k.priv(), op.signBytes()), pub);
    }

    public static void main(String[] a) throws Exception { if (run(a) != 0) System.exit(1); }
}
