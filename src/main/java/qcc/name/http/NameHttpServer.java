package qcc.name.http;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import qcc.name.chain.ChainUnavailableException;
import qcc.name.chain.ChainView;
import qcc.name.codec.QccCanonicalReader;
import qcc.name.codec.Sha3;
import qcc.name.crypto.ClusterCipher;
import qcc.name.crypto.MlDsa87;
import qcc.name.crypto.NodeKeyVault;
import qcc.name.frame.Ack;
import qcc.name.frame.FrameCodec;
import qcc.name.node.NameNode;
import qcc.name.node.SubmitResult;
import qcc.name.node.VerifyResult;
import qcc.name.op.NameOp;
import qcc.name.op.RegisterOp;
import qcc.name.op.UnregisterOp;
import qcc.name.protocol.StrictJson;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;

/**
 * 节点 HTTP 接口（JDK 自带 com.sun.net.httpserver，零依赖）。
 * ═══ 对外（JSON）══════════════════════════════════════════════════
 *   POST /v1/register    {"chain","address","name","timestamp","credentialHash","sig"}
 *   POST /v1/unregister  {"chain","address","name","timestamp","regSeq","sig"}
 *        sig = ML-DSA-87 对签名字符串的签名（hex）；签名字符串由服务端按同样字段重建：
 *        QNS1|register|chain|address|name|timestamp|credentialHash
 *        QNS1|unregister|chain|address|name|timestamp|regSeq
 *   GET  /v1/verify?name=&address=      → match/status + L1 证据（signString、sig、opBytes）
 *   GET  /v1/pubkey?address=            → 链上公钥 hex
 *   GET  /v1/status                     → 节点 term/seq/execHash/角色
 *   GET  /v1/node/proof?nonce=64位hex    → 节点身份证明：nodeId、公钥、nodesTx 与 nodeId 私钥签名
 * ═══ 节点间（AES-256-GCM 密文，见 ClusterCipher；持有 clusterKey 即可访问，不依赖 IP）═══
 *   POST /internal/frame                str(from) bytes(data) → ack（拒收返回 409）
 *   POST /internal/pull                 u64(from) u32(max) → list
 *   POST /internal/heartbeat            → heartbeat
 *   POST /internal/submit               bytes(op)|bytes(sig) → JSON 结果（非主节点透传）
 *   POST /internal/cluster              JSON：hello（加入 / 上报 / 追平）、announce（主节点广播成员表）、vote（选举）
 *   解密失败（密钥不一致、时间偏差 >60s、重放）返回 403
 * ═══ 管理（只允许本机 127.0.0.1 访问）════════════════════════════════
 *   POST /admin/promote[?term=N]        手动接班（核心节点 <3 时用）：本节点成为主节点，term 默认 +1
 *   POST /admin/rejoin?peer=节点地址     清空本地数据，从 peer 全量重新同步（分叉时会自动执行）
 *   POST /admin/remove?id=节点地址       主节点上移除已永久下线的成员（否则一直计入过半数）
 * ═══ 限流 ═════════════════════════════════════════════════════════
 *   /v1/* 按来源 IP 每分钟：写 WRITE_PER_MIN、读 READ_PER_MIN；节点 IP 与回环不限。超限返回 429。
 * 对外接口为明文 HTTP（v1.0 测试版）；节点钱包签名 verify 响应将在钱包托管完成后加入。
 */
public final class NameHttpServer {

    private final NameNode node;
    private final ChainView chain;
    private final Set<InetAddress> internalAllowed;    // 仅用于限流豁免
    private final ClusterCipher cipher;
    private java.util.concurrent.ExecutorService pool;
    private final HttpServer server;
    private final RateLimiter limiter;
    static final int WRITE_PER_MIN = 60;
    static final int READ_PER_MIN  = 1200;

    private final StaticFiles web;                     // null = 不提供静态网站

    public NameHttpServer(NameNode node, ChainView chain, InetSocketAddress bind, Set<InetAddress> internalAllowed,
                          ClusterCipher cipher) throws Exception {
        this(node, chain, HttpServer.create(bind, 256), internalAllowed, cipher, null);
    }

    /**
     * @param server 已创建的 HttpServer 或 HttpsServer（HTTPS 由调用方配置证书）
     * @param webDir 静态网站目录；null 或不存在则不提供
     */
    public NameHttpServer(NameNode node, ChainView chain, HttpServer server, Set<InetAddress> internalAllowed,
                          ClusterCipher cipher, java.nio.file.Path webDir) throws Exception {
        this.node = node;
        this.cipher = cipher;
        this.chain = chain;
        this.internalAllowed = internalAllowed;
        this.server = server;
        this.web = webDir != null ? new StaticFiles(webDir) : null;   // 目录可在运行中创建，无需重启
        this.limiter = new RateLimiter(WRITE_PER_MIN, READ_PER_MIN, internalAllowed);
        pool = Executors.newFixedThreadPool(16, r -> { Thread t = new Thread(r, "qccname-http"); t.setDaemon(true); return t; });
        server.setExecutor(pool);
        route("/v1/register",       limited(true,  this::register));
        route("/v1/unregister",     limited(true,  this::unregister));
        route("/v1/verify",         limited(false, this::verify));
        route("/v1/check",          limited(false, this::check));
        route("/v1/address",        limited(false, this::address));
        route("/v1/reserved",       limited(false, this::reserved));
        route("/v1/pubkey",         limited(false, this::pubkey));
        route("/v1/status",         limited(false, this::status));
        route("/v1/node/proof",     limited(false, this::nodeProof));
        route("/admin/promote",     admin(this::adminPromote));
        route("/admin/rejoin",      admin(this::adminRejoin));
        sealed("/internal/frame",     this::frame);
        sealed("/internal/pull",      this::pull);
        sealed("/internal/heartbeat", body -> FrameCodec.encodeHeartbeat(node.heartbeat()));
        sealed("/internal/submit",    this::internalSubmit);
        sealed("/internal/cluster",   node::onCluster);
        route("/admin/remove",      admin(this::adminRemove));
        route("/",                  ex -> {                   // 其余路径：静态网站
            if (web != null) web.handle(ex);
            else Http.json(ex, 404, Map.of("error", "not found"));
        });
    }

    private volatile NodeKeyVault nodeKey;            // null = 本节点不提供节点证明（backup）
    private volatile String nodesTx = "";

    /** 节点私钥与当前 qcc-name-nodes 交易 hash（启动时由 NodeMain 设置）。 */
    public void setNodeKey(NodeKeyVault key, String nodesTx) {
        this.nodeKey = key;
        this.nodesTx = nodesTx == null ? "" : nodesTx;
    }

    public void start() { server.start(); }
    public void stop()  { server.stop(0); pool.shutdownNow(); }

    // ── 对外接口 ──────────────────────────────────────────────────

    private void register(HttpExchange ex) throws Exception {
        if (!post(ex)) return;
        Map<String, Object> j = StrictJson.parseObject(Http.body(ex));
        NameOp op = new RegisterOp(StrictJson.str(j, "chain"), StrictJson.str(j, "address"),
                StrictJson.str(j, "name"), StrictJson.num(j, "timestamp"), StrictJson.str(j, "credentialHash"));
        submit(ex, op, StrictJson.str(j, "sig"), optHex(j, "pubkey"));
    }

    private void unregister(HttpExchange ex) throws Exception {
        if (!post(ex)) return;
        Map<String, Object> j = StrictJson.parseObject(Http.body(ex));
        NameOp op = new UnregisterOp(StrictJson.str(j, "chain"), StrictJson.str(j, "address"),
                StrictJson.str(j, "name"), StrictJson.num(j, "timestamp"), StrictJson.num(j, "regSeq"));
        submit(ex, op, StrictJson.str(j, "sig"), optHex(j, "pubkey"));
    }

    /** 可选的 hex 字段（如 pubkey）：没有或为空返回空数组。 */
    private static String optHex(Map<String, Object> j, String k) {
        Object v = j.get(k);
        return v instanceof String s ? s.trim() : "";
    }

    private void submit(HttpExchange ex, NameOp op, String sigHex, String pubkeyHex) throws Exception {
        byte[] sig, pk;
        try { sig = Sha3.fromHex(sigHex); pk = pubkeyHex.isEmpty() ? new byte[0] : Sha3.fromHex(pubkeyHex); }
        catch (RuntimeException e) { Http.json(ex, 400, Map.of("status", "DROPPED", "message", "sig / pubkey 不是 hex")); return; }
        SubmitResult r = node.submit(op.toBytes(), sig, pk);
        Http.json(ex, httpCode(r), resultJson(r));
    }

    private void verify(HttpExchange ex) throws Exception {
        Map<String, String> q = Http.query(ex);
        String name = q.get("name"), address = q.getOrDefault("address", "");
        if (name == null) { Http.json(ex, 400, Map.of("error", "缺少 name")); return; }
        VerifyResult v = node.verify(name, address);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("match", v.match());
        m.put("status", v.status().name());
        m.put("name", v.name());
        m.put("reserved", v.reserved());
        if (v.reserved()) {                                   // 保留名：按 Reserved 表回答，不查质押、无质押凭证
            if (v.status() != VerifyResult.Status.NOT_FOUND) m.put("address", v.address());
            m.put("reservedTx", v.reservedTx());
            m.put("regSeq", v.regSeq());
            m.put("creds", Map.of());
            NameOp op = NameOp.fromBytes(v.opBytes());
            Map<String, Object> ev = new LinkedHashMap<>();
            ev.put("signString", op.toSign());
            ev.put("opBytes", Base64.getEncoder().encodeToString(v.opBytes()));
            ev.put("chainTx", "/v1/hash/" + v.reservedTx());
            m.put("evidence", ev);
        } else if (v.status() != VerifyResult.Status.NOT_FOUND) {
            m.put("address", v.address());
            m.put("regSeq", v.regSeq());
            m.put("credentialHash", v.credentialHash());
            m.put("creds", Map.of(node.pledgeTag(), v.credentialHash()));   // 链上三要素：address + tag + hash
            NameOp op = NameOp.fromBytes(v.opBytes());
            Map<String, Object> ev = new LinkedHashMap<>();
            ev.put("signString", op.toSign());
            ev.put("sig", Sha3.toHex(v.signature()));
            ev.put("opBytes", Base64.getEncoder().encodeToString(v.opBytes()));
            if (v.pubkey() != null) ev.put("pubkey", Sha3.toHex(v.pubkey()));   // 链上无公钥时给出（须推导出 address）
            m.put("evidence", ev);
        }
        m.put("asOf", v.asOfSeq());
        m.put("term", v.term());
        m.put("nodeId", v.nodeId());
        Http.json(ex, 200, m);
    }

    /**
     * GET /v1/address?address= —— 按地址反查名下的名字（每个 tag 至多一个）及其链上凭证。
     * 每个名字都实时查链：status = MATCH / REVOKED / UNVERIFIED，与 verify 同义。
     * creds = {质押 tag: txHash}，调用方可拿 address + tag + hash 直接向 QCC 公链独立核对。
     */
    private void address(HttpExchange ex) throws Exception {
        String a = Http.query(ex).get("address");
        if (a == null || a.isBlank()) { Http.json(ex, 400, Map.of("error", "缺少 address")); return; }
        a = a.trim();
        NameNode.AddressNames r = node.namesOf(a);
        List<Map<String, Object>> list = new ArrayList<>();
        for (NameNode.HeldName h : r.names()) {
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("name", h.name());
            e.put("match", h.status() == VerifyResult.Status.MATCH);
            e.put("status", h.status().name());
            e.put("regSeq", h.regSeq());
            e.put("regTime", h.regTime());
            e.put("reserved", h.reserved());
            if (h.reserved()) { e.put("reservedTx", h.reservedTx()); e.put("creds", Map.of()); }
            else e.put("creds", Map.of(node.pledgeTag(), h.credentialHash()));
            list.add(e);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("address", a);
        m.put("names", list);
        m.put("asOf", r.asOfSeq());
        m.put("term", r.term());
        m.put("nodeId", r.nodeId());
        Http.json(ex, 200, m);
    }

    /**
     * GET /v1/reserved —— 当前生效的 Reserved 表与全部历史版本（seq / 交易 hash / 高度 / 日志序号）。
     * 应用可把 history 的交易 hash 记在本地，与链上 GET /v1/hash/{tx} 逐一核对（from 必须是 publisher）。
     */
    private void reserved(HttpExchange ex) throws Exception {
        NameNode.ReservedInfo r = node.reservedInfo();
        List<Map<String, Object>> hist = new ArrayList<>();
        for (qcc.name.core.NameState.ReservedVersion v : r.history()) {
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("seq", v.seq());
            e.put("tx", v.tx());
            e.put("height", v.height());
            e.put("logSeq", v.logSeq());
            e.put("documentHash", v.documentHash());
            hist.add(e);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("enabled", r.enabled());
        m.put("publisher", r.publisher());
        m.put("seq", hist.isEmpty() ? 0 : hist.getLast().get("seq"));
        m.put("names", new LinkedHashMap<>(r.names()));
        m.put("history", hist);
        m.put("asOf", r.asOfSeq());
        m.put("term", r.term());
        m.put("nodeId", r.nodeId());
        Http.json(ex, 200, m);
    }

    /** GET /v1/check?name=&address=&credentialHash= —— 注册前预检，不写入、不需要签名。 */
    private void check(HttpExchange ex) throws Exception {
        Map<String, String> q = Http.query(ex);
        if (q.get("name") == null) { Http.json(ex, 400, Map.of("error", "缺少 name")); return; }
        NameNode.CheckResult r = node.check(q.get("name"), q.get("address"), q.get("credentialHash"));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", q.get("name").trim().toLowerCase());
        m.put("available", r.available());
        m.put("resultCode", r.resultCode());
        m.put("reason", r.reason());
        if (r.holder() != null) m.put("holder", r.holder());
        Http.json(ex, 200, m);
    }

    private void pubkey(HttpExchange ex) throws Exception {
        String a = Http.query(ex).get("address");
        if (a == null) { Http.json(ex, 400, Map.of("error", "缺少 address")); return; }
        try {
            NameNode.KeyInfo k = node.pubkeyOf(a);
            if (k == null) { Http.json(ex, 404, Map.of("address", a, "found", false)); return; }
            Http.json(ex, 200, Map.of("address", a, "found", true, "source", k.source(), "pubkey", Sha3.toHex(k.pubkey())));
        } catch (ChainUnavailableException e) {
            Http.json(ex, 503, Map.of("error", "公链不可达"));
        }
    }

    private void status(HttpExchange ex) throws Exception {
        var h = node.heartbeat();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("nodeId", h.nodeId());
        m.put("primary", h.primary());
        m.put("primaryId", node.primaryId());
        m.put("term", h.term());
        m.put("seq", h.seq());
        m.put("execHash", Sha3.toHex(h.execHash()));
        m.put("role", node.isPrimary() ? "primary" : node.isCore() ? "core" : node.joined() ? "observer" : "joining");
        m.put("cluster", node.clusterTable());
        m.put("signer", MlDsa87.source());
        Http.json(ex, 200, m);
    }

    /**
     * GET /v1/node/proof?nonce=64位hex → 节点身份证明。
     *   signString = QNN1|proof|chain|nodeId|nonce|timestamp|nodesTx
     *   sig        = nodeId 私钥对 signString（UTF-8）的 ML-DSA-87 签名
     * 客户端核对：QccAddress(pubkey) = 链上 qcc-name-nodes 中本 IP 对应的 nodeId，nonce 是自己发的，再验签。
     */
    private void nodeProof(HttpExchange ex) throws Exception {
        NodeKeyVault k = nodeKey;
        if (k == null) { Http.json(ex, 503, Map.of("error", "this node has no node key (backup node)")); return; }
        String nonce = Http.query(ex).getOrDefault("nonce", "").strip().toLowerCase();
        if (!Sha3.isHex32(nonce)) { Http.json(ex, 400, Map.of("error", "nonce must be 64 hex chars (32 random bytes)")); return; }
        long ts = System.currentTimeMillis();
        String chainId = node.protocol().chain;
        String tx = nodesTx;
        String signString = "QNN1|proof|" + chainId + "|" + k.nodeId() + "|" + nonce + "|" + ts + "|" + tx;
        byte[] sig = k.sign(signString.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("nodeId", k.nodeId());
        m.put("chain", chainId);
        m.put("nonce", nonce);
        m.put("timestamp", ts);
        m.put("nodesTx", tx);
        m.put("public", false);
        m.put("pubkey", k.publicKeyHex());
        m.put("signString", signString);
        m.put("sig", Sha3.toHex(sig));
        Http.json(ex, 200, m);
    }

    // ── 节点间接口 ────────────────────────────────────────────────

    /** 返回 null 表示拒收（409）。 */
    private byte[] frame(byte[] body) {
        QccCanonicalReader r = new QccCanonicalReader(body);
        String from = r.str();
        byte[] data = r.bytes();
        r.finish();
        Ack a = node.onFrame(from, FrameCodec.decodeData(data));
        return a == null ? null : FrameCodec.encodeAck(a);
    }

    private byte[] pull(byte[] body) {
        QccCanonicalReader r = new QccCanonicalReader(body);
        long from = r.u64();
        int max = (int) Math.min(1024, r.u32());
        r.finish();
        return FrameCodec.encodeList(node.pull(from, max));
    }

    private byte[] internalSubmit(byte[] body) {
        QccCanonicalReader r = new QccCanonicalReader(body);
        byte[] op = r.bytes(), sig = r.bytes(), pk = r.bytes();
        r.finish();
        return Json.write(resultJson(node.submit(op, sig, pk))).getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    // ── 工具 ──────────────────────────────────────────────────────

    interface Handler { void handle(HttpExchange ex) throws Exception; }

    private void route(String path, Handler h) {
        boolean api = path.startsWith("/v1/");
        server.createContext(path, ex -> {
            if (api) {                                         // 允许网页应用跨域调用对外接口
                var hd = ex.getResponseHeaders();
                hd.set("Access-Control-Allow-Origin", "*");
                hd.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                hd.set("Access-Control-Allow-Headers", "Content-Type");
                hd.set("Access-Control-Max-Age", "86400");
                if ("OPTIONS".equals(ex.getRequestMethod())) { ex.sendResponseHeaders(204, -1); ex.close(); return; }
            }
            try {
                h.handle(ex);
            } catch (IllegalArgumentException | IllegalStateException e) {
                Http.json(ex, 400, Map.of("status", "DROPPED", "message", String.valueOf(e.getMessage())));
            } catch (Exception e) {
                Http.json(ex, 500, Map.of("error", e.getClass().getSimpleName() + ": " + e.getMessage()));
            }
        });
    }

    private Handler limited(boolean write, Handler h) {
        return ex -> {
            if (!limiter.allow(ex.getRemoteAddress().getAddress(), write)) {
                Http.json(ex, 429, Map.of("status", "DROPPED", "resultCode", -1, "seq", 0,
                        "message", "请求过于频繁，每分钟上限 " + (write ? WRITE_PER_MIN : READ_PER_MIN)));
                return;
            }
            h.handle(ex);
        };
    }

    private Handler admin(Handler h) {
        return ex -> {
            if (!ex.getRemoteAddress().getAddress().isLoopbackAddress()) {
                Http.json(ex, 403, Map.of("error", "管理接口只允许本机访问"));
                return;
            }
            if (!post(ex)) return;
            h.handle(ex);
        };
    }

    private void adminPromote(HttpExchange ex) throws Exception {
        String t = Http.query(ex).get("term");                 // 可省略：默认当前 term + 1
        node.promote(t == null ? node.term() + 1 : Integer.parseInt(t));
        System.out.println("[admin] 手动接班 term=" + node.term() + "，本节点为主");
        status(ex);
    }

    private void adminRemove(HttpExchange ex) throws Exception {
        String id = Http.query(ex).get("id");
        if (id == null) { Http.json(ex, 400, Map.of("error", "缺少 id")); return; }
        node.removeMember(id);
        System.out.println("[admin] 移除成员 " + id);
        status(ex);
    }

    private void adminRejoin(HttpExchange ex) throws Exception {
        String peer = Http.query(ex).get("peer");
        if (peer == null) { Http.json(ex, 400, Map.of("error", "缺少 peer（新主节点地址）")); return; }
        boolean ok = node.rejoinFrom(peer);
        System.out.println("[admin] 从 " + peer + " 全量重新同步：" + (ok ? "完成" : "未完成") + "，当前 " + node.maxSeq() + " 帧");
        status(ex);
    }

    interface SealedHandler { byte[] handle(byte[] plain) throws Exception; }

    /** 节点间接口：解密请求 → 处理 → 加密响应（绑定请求 nonce）。解密失败 403；处理返回 null 时 409。 */
    private void sealed(String path, SealedHandler h) {
        route(path, ex -> {
            if (!post(ex)) return;
            ClusterCipher.Opened req;
            try {
                req = cipher.openRequest(path, Http.body(ex));
            } catch (SecurityException e) {
                Http.bin(ex, 403, new byte[0]);
                return;
            }
            byte[] out = h.handle(req.plain());
            if (out == null) { Http.bin(ex, 409, new byte[0]); return; }
            Http.bin(ex, 200, cipher.sealResponse(path, out, req.nonce()));
        });
    }

    private static boolean post(HttpExchange ex) throws Exception {
        if ("POST".equals(ex.getRequestMethod())) return true;
        Http.json(ex, 405, Map.of("error", "需要 POST"));
        return false;
    }

    private static int httpCode(SubmitResult r) {
        return switch (r.status()) {
            case OK, REJECTED -> 200;
            case PENDING -> 202;
            case DROPPED -> 400;
            case UNAVAILABLE -> 503;
        };
    }

    static Map<String, Object> resultJson(SubmitResult r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", r.status().name());
        m.put("resultCode", r.resultCode());
        m.put("seq", r.seq());
        m.put("message", r.message() == null ? "" : r.message());
        return m;
    }

    static SubmitResult parseResult(Map<String, Object> j) {
        return new SubmitResult(SubmitResult.Status.valueOf(StrictJson.str(j, "status")),
                (int) StrictJson.num(j, "resultCode"), StrictJson.num(j, "seq"), StrictJson.strAllowEmpty(j, "message"));
    }

}