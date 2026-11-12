package qcc.name.http;

import qcc.name.Check;
import qcc.name.chain.MockChainView;
import qcc.name.chain.MultiChainView;
import qcc.name.codec.Sha3;
import qcc.name.crypto.ClusterCipher;
import qcc.name.crypto.MlDsa87;
import qcc.name.crypto.QccAddress;
import qcc.name.dev.DevChainServer;
import qcc.name.node.NameNode;
import qcc.name.node.NodeConfig;
import qcc.name.node.SubmitResult;
import qcc.name.op.RegisterOp;
import qcc.name.protocol.NameProtocol;
import qcc.name.protocol.ProtocolLoader;
import qcc.name.store.FrameStore;

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.*;

/**
 * 网络层自测：ClusterCipher、真实 HTTP 上的 2 核心 + 1 冗余节点加密同步、MultiChainView 故障切换。
 * 全部在 127.0.0.1 随机端口，不连外网。
 */
public final class NetSelfTest {

    public static int run(String[] a) throws Exception {
        Check c = new Check();
        cipher(c);
        cluster(c);
        multiChain(c);
        return c.failed();
    }

    // ── ClusterCipher ─────────────────────────────────────────────

    static void cipher(Check c) {
        byte[] k = Sha3.fromHex(qcc.name.config.QccNameConfig.newKeyHex());
        ClusterCipher A = new ClusterCipher(k), B = new ClusterCipher(k);
        ClusterCipher X = new ClusterCipher(Sha3.fromHex(qcc.name.config.QccNameConfig.newKeyHex()));
        byte[] msg = "hello frame".getBytes(StandardCharsets.UTF_8);

        byte[][] req = A.sealRequest("/internal/frame", msg);
        ClusterCipher.Opened o = B.openRequest("/internal/frame", req[0]);
        c.ck(Arrays.equals(o.plain(), msg), "同密钥：请求加解密往返");
        c.ck(c.throwsAny(() -> B.openRequest("/internal/frame", req[0])), "同一请求重放 → 拒绝");
        c.ck(c.throwsAny(() -> X.openRequest("/internal/frame", A.sealRequest("/internal/frame", msg)[0])), "不同 clusterKey → 拒绝");
        c.ck(c.throwsAny(() -> B.openRequest("/internal/pull", A.sealRequest("/internal/frame", msg)[0])), "换 path 使用 → 拒绝");
        byte[] t = A.sealRequest("/internal/frame", msg)[0];
        t[t.length - 20] ^= 1;
        c.ck(c.throwsAny(() -> B.openRequest("/internal/frame", t)), "篡改一个字节 → 拒绝");
        byte[] old = A.sealRequest("/internal/frame", msg)[0];
        java.nio.ByteBuffer.wrap(old, 5, 8).putLong(System.currentTimeMillis() - 120_000);
        c.ck(c.throwsAny(() -> B.openRequest("/internal/frame", old)), "时间戳偏差 120s → 拒绝");

        byte[][] r2 = A.sealRequest("/internal/pull", msg);
        ClusterCipher.Opened o2 = B.openRequest("/internal/pull", r2[0]);
        byte[] resp = B.sealResponse("/internal/pull", "list".getBytes(), o2.nonce());
        c.ck(Arrays.equals(A.openResponse("/internal/pull", resp, r2[1]), "list".getBytes()), "响应绑定请求 nonce：往返");
        byte[][] r3 = A.sealRequest("/internal/pull", msg);
        c.ck(c.throwsAny(() -> A.openResponse("/internal/pull", resp, r3[1])), "响应拿去冒充另一请求的响应 → 拒绝");
    }

    // ── 2 核心 + 1 冗余，真实 HTTP + 加密 ─────────────────────────

    static void cluster(Check c) throws Exception {
        NameProtocol p = ProtocolLoader.loadFile(Path.of("testdata/qcc-name-test-v1.0.0.json"), null);
        MockChainView chain = new MockChainView(System.currentTimeMillis());
        Path root = Files.createTempDirectory("qccname-net");
        byte[] key = Sha3.fromHex(qcc.name.config.QccNameConfig.newKeyHex());
        String[] ids = {"QNet0aaaaaaaaaaaaaaaaaaaaaaaaaaaa1", "QNet1bbbbbbbbbbbbbbbbbbbbbbbbbbbb2", "QNetObscccccccccccccccccccccccccc3"};
        int[] ports = {freePort(), freePort(), freePort()};
        Map<String, String> urls = new LinkedHashMap<>();
        for (int i = 0; i < 3; i++) urls.put(ids[i], "http://127.0.0.1:" + ports[i]);
        List<String> order = List.of(ids[0], ids[1]), obs = List.of(ids[2]);

        List<NameNode> nodes = new ArrayList<>();
        List<NameHttpServer> servers = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            ClusterCipher ci = new ClusterCipher(key);
            NameNode n = new NameNode(new NodeConfig(ids[i], root.resolve("n" + i), order, obs, p, "qccname-net",
                    chain, new HttpTransport(urls, ci), System::currentTimeMillis));
            NameHttpServer s = new NameHttpServer(n, chain, new InetSocketAddress("127.0.0.1", ports[i]), Set.of(), ci);
            s.start();
            nodes.add(n);
            servers.add(s);
        }
        try {
            SecureRandom rnd = new SecureRandom();
            List<String> names = new ArrayList<>();
            String firstAddr = null;
            for (int i = 0; i < 5; i++) {
                MlDsa87.Keys kp = MlDsa87.generate();
                String addr = QccAddress.derive(kp.pub());
                chain.putPubkey(addr, kp.pub());
                byte[] h = new byte[32]; rnd.nextBytes(h);
                String cred = Sha3.toHex(h);
                chain.lock(addr, p.pledgeTag, cred, "QCC", 1_000_000_000L, "QFrom");
                RegisterOp op = new RegisterOp(p.chain, addr, "net" + i + ".qcc", System.currentTimeMillis(), cred);
                NameNode entry = nodes.get(i % 3);            // 轮流从主 / 备 / 冗余提交（后两者透传主节点）
                SubmitResult r = entry.submit(op.toBytes(), MlDsa87.sign(kp.priv(), op.signBytes()));
                c.ck(r.status() == SubmitResult.Status.OK, "经节点 " + (i % 3) + " 注册 net" + i + ".qcc → " + r);
                names.add(op.name);
                if (i == 0) firstAddr = addr;
            }
            Thread.sleep(500);                                  // 冗余节点为异步推送
            NameNode n0 = nodes.get(0), n1 = nodes.get(1), ob = nodes.get(2);
            c.ck(n1.maxSeq() == n0.maxSeq() && n1.execHex().equals(n0.execHex()), "备节点同步（加密通道）seq=" + n1.maxSeq());
            c.ck(ob.maxSeq() == n0.maxSeq() && ob.execHex().equals(n0.execHex()), "冗余节点同步 seq=" + ob.maxSeq());
            c.ck(ob.verify(names.get(0), firstAddr).match(), "冗余节点 verify 可用");
            c.ck(!ob.isPrimary(), "冗余节点永不为主");

            // 冗余节点离线后补齐：停掉服务，主节点继续写，再恢复 → syncTick 追平
            servers.get(2).stop();
            MlDsa87.Keys kp = MlDsa87.generate();
            String addr = QccAddress.derive(kp.pub());
            chain.putPubkey(addr, kp.pub());
            String cred = Sha3.toHex(Sha3.hashUtf8("late"));
            chain.lock(addr, p.pledgeTag, cred, "QCC", 1_000_000_000L, "QFrom");
            RegisterOp op = new RegisterOp(p.chain, addr, "late.qcc", System.currentTimeMillis(), cred);
            SubmitResult r = n0.submit(op.toBytes(), MlDsa87.sign(kp.priv(), op.signBytes()));
            c.ck(r.status() == SubmitResult.Status.OK, "冗余节点离线时写入不受影响 → " + r);
            Thread.sleep(300);
            c.ck(ob.maxSeq() < n0.maxSeq(), "冗余节点落后 " + (n0.maxSeq() - ob.maxSeq()) + " 帧");
            ob.syncTick();
            c.ck(ob.maxSeq() == n0.maxSeq() && ob.execHex().equals(n0.execHex()), "syncTick 追平");

            // 错误密钥的"节点"：访问 /internal/* 一律 403，拿不到数据
            HttpTransport bad = new HttpTransport(urls, new ClusterCipher(Sha3.fromHex(qcc.name.config.QccNameConfig.newKeyHex())));
            c.ck(bad.pull(ids[0], 1, 10) == null && bad.heartbeat(ids[0]) == null, "错误 clusterKey：pull / heartbeat 被拒（403）");
            HttpResponse<byte[]> plain = HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(urls.get(ids[0]) + "/internal/heartbeat"))
                    .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofByteArray());
            c.ck(plain.statusCode() == 403, "明文访问 /internal/heartbeat → " + plain.statusCode());

            // 按地址反查：名字 + 链上凭证（三要素）
            String body = new String(HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(urls.get(ids[1])
                    + "/v1/address?address=" + firstAddr)).build(), HttpResponse.BodyHandlers.ofByteArray()).body(), StandardCharsets.UTF_8);
            c.ck(body.contains("\"name\":\"" + names.get(0) + "\"") && body.contains("\"status\":\"MATCH\"") && body.contains("\"creds\":{\"qccio\":\""),
                    "GET /v1/address 反查到名字与 creds：" + body.substring(0, Math.min(160, body.length())) + "…");
            String none = new String(HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(urls.get(ids[1])
                    + "/v1/address?address=QNobodyAaaaaaaaaaaaaaaaaaaaaaaaaa")).build(), HttpResponse.BodyHandlers.ofByteArray()).body(), StandardCharsets.UTF_8);
            c.ck(none.contains("\"names\":[]"), "无名字的地址 → names 为空");
        } finally {
            for (NameHttpServer s : servers) try { s.stop(); } catch (Exception ignored) { }
            for (NameNode n : nodes) n.close();
            FrameStore.deleteTree(root);
        }
    }

    // ── MultiChainView ────────────────────────────────────────────

    static void multiChain(Check c) throws Exception {
        int dead = freePort(), p1 = freePort(), p2 = freePort();
        var s1 = new DevChainServer().start(p1);
        var s2 = new DevChainServer().start(p2);
        try {
            MlDsa87.Keys kp = MlDsa87.generate();
            String addr = "QChainUser" + "z".repeat(24);
            String body = "{\"address\":\"" + addr + "\",\"pubkey\":\"" + Sha3.toHex(kp.pub()) + "\"}";
            for (int port : new int[]{p1, p2})
                HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/dev/user"))
                        .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.discarding());

            MultiChainView m = new MultiChainView(List.of("http://127.0.0.1:" + dead, "http://127.0.0.1:" + p1, "http://127.0.0.1:" + p2));
            c.ck(Arrays.equals(m.pubkeyOf(addr), kp.pub()), "第 1 个链节点宕机 → 自动切到下一个，公钥正确");
            c.ck(m.describe().contains("(暂停)"), "宕机节点被暂停：" + m.describe());
            c.ck(m.pledgeGoneConfirmed(addr, "qccio", "00".repeat(32)), "2 个在线链节点都确认质押不存在 → 可回收");

            MultiChainView one = new MultiChainView(List.of("http://127.0.0.1:" + dead, "http://127.0.0.1:" + p1));
            c.ck(!one.pledgeGoneConfirmed(addr, "qccio", "00".repeat(32)), "只有 1 个链节点在线 → 不回收（确认不足）");
            MultiChainView none = new MultiChainView(List.of("http://127.0.0.1:" + dead));
            c.ck(c.throwsAny(() -> none.authPledge(addr, "qccio", "00".repeat(32))), "全部链节点不可达 → ChainUnavailable（拒绝写入，不误判）");
        } finally {
            s1.stop(0);
            s2.stop(0);
        }
    }

    static int freePort() throws Exception { try (ServerSocket s = new ServerSocket(0)) { return s.getLocalPort(); } }

    public static void main(String[] a) throws Exception { if (run(a) != 0) System.exit(1); }
}
