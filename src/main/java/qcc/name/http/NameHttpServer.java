package qcc.name.http;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import qcc.name.chain.ChainUnavailableException;
import qcc.name.chain.ChainView;
import qcc.name.codec.QccCanonicalReader;
import qcc.name.codec.Sha3;
import qcc.name.crypto.MlDsa87;
import qcc.name.frame.Ack;
import qcc.name.frame.FrameCodec;
import qcc.name.frame.FramePacket;
import qcc.name.node.NameNode;
import qcc.name.node.SubmitResult;
import qcc.name.node.VerifyResult;
import qcc.name.op.NameOp;
import qcc.name.op.RegisterOp;
import qcc.name.op.UnregisterOp;
import qcc.name.protocol.StrictJson;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;

/**
 * 节点 HTTP 接口（JDK 自带 com.sun.net.httpserver，零依赖）。
 *
 * ═══ 对外（JSON）══════════════════════════════════════════════════
 *   POST /v1/register    {"chain","address","name","timestamp","credentialHash","sig"}
 *   POST /v1/unregister  {"chain","address","name","timestamp","regSeq","sig"}
 *        sig = ML-DSA-87 对签名字符串的签名（hex）；签名字符串由服务端按同样字段重建：
 *        QNS1|register|chain|address|name|timestamp|credentialHash
 *        QNS1|unregister|chain|address|name|timestamp|regSeq
 *   GET  /v1/verify?name=&address=      → match/status + L1 证据（signString、sig、opBytes）
 *   GET  /v1/pubkey?address=            → 链上公钥 hex
 *   GET  /v1/status                     → 节点 term/seq/execHash/角色
 *
 * ═══ 节点间（二进制 FrameCodec，只放行回环地址与 peers 中的主机）═══════
 *   POST /internal/frame?from=          data → ack（拒收返回 409）
 *   GET  /internal/pull?from=&max=      list
 *   GET  /internal/heartbeat            heartbeat
 *   POST /internal/submit               bytes(op)|bytes(sig) → JSON 结果（非主节点透传）
 *
 * ═══ 开发模式 ═════════════════════════════════════════════════════
 *   ssl=false 时用明文 HTTP（-Dqccname.dev=true），免去本地配置证书。
 *   生产模式用 HttpsServer + keystore（各节点独立域名与证书，P1 以证书证明节点身份）。
 */
public final class NameHttpServer {

    private final NameNode node;
    private final ChainView chain;
    private final Set<InetAddress> internalAllowed;
    private final HttpServer server;

    public NameHttpServer(NameNode node, ChainView chain, InetSocketAddress bind, Set<InetAddress> internalAllowed,
                          String keystore, String keystorePass) throws Exception {
        this.node = node;
        this.chain = chain;
        this.internalAllowed = Set.copyOf(internalAllowed);
        if (keystore == null) {
            server = HttpServer.create(bind, 256);
        } else {
            HttpsServer s = HttpsServer.create(bind, 256);
            s.setHttpsConfigurator(new HttpsConfigurator(sslContext(keystore, keystorePass)));
            server = s;
        }
        server.setExecutor(Executors.newFixedThreadPool(16));
        route("/v1/register",       this::register);
        route("/v1/unregister",     this::unregister);
        route("/v1/verify",         this::verify);
        route("/v1/pubkey",         this::pubkey);
        route("/v1/status",         this::status);
        route("/internal/frame",    internal(this::frame));
        route("/internal/pull",     internal(this::pull));
        route("/internal/heartbeat", internal(ex -> Http.bin(ex, 200, FrameCodec.encodeHeartbeat(node.heartbeat()))));
        route("/internal/submit",   internal(this::internalSubmit));
    }

    public void start() { server.start(); }
    public void stop()  { server.stop(0); }

    // ── 对外接口 ──────────────────────────────────────────────────

    private void register(HttpExchange ex) throws Exception {
        if (!post(ex)) return;
        Map<String, Object> j = StrictJson.parseObject(Http.body(ex));
        NameOp op = new RegisterOp(StrictJson.str(j, "chain"), StrictJson.str(j, "address"),
                StrictJson.str(j, "name"), StrictJson.num(j, "timestamp"), StrictJson.str(j, "credentialHash"));
        submit(ex, op, StrictJson.str(j, "sig"));
    }

    private void unregister(HttpExchange ex) throws Exception {
        if (!post(ex)) return;
        Map<String, Object> j = StrictJson.parseObject(Http.body(ex));
        NameOp op = new UnregisterOp(StrictJson.str(j, "chain"), StrictJson.str(j, "address"),
                StrictJson.str(j, "name"), StrictJson.num(j, "timestamp"), StrictJson.num(j, "regSeq"));
        submit(ex, op, StrictJson.str(j, "sig"));
    }

    private void submit(HttpExchange ex, NameOp op, String sigHex) throws Exception {
        byte[] sig;
        try { sig = Sha3.fromHex(sigHex); }
        catch (RuntimeException e) { Http.json(ex, 400, Map.of("status", "DROPPED", "message", "sig 不是 hex")); return; }
        SubmitResult r = node.submit(op.toBytes(), sig);
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
        if (v.status() != VerifyResult.Status.NOT_FOUND) {
            m.put("address", v.address());
            m.put("regSeq", v.regSeq());
            m.put("credentialHash", v.credentialHash());
            NameOp op = NameOp.fromBytes(v.opBytes());
            Map<String, Object> ev = new LinkedHashMap<>();
            ev.put("signString", op.toSign());
            ev.put("sig", Sha3.toHex(v.signature()));
            ev.put("opBytes", Base64.getEncoder().encodeToString(v.opBytes()));
            m.put("evidence", ev);
        }
        m.put("asOf", v.asOfSeq());
        m.put("term", v.term());
        m.put("nodeId", v.nodeId());
        Http.json(ex, 200, m);
    }

    private void pubkey(HttpExchange ex) throws Exception {
        String a = Http.query(ex).get("address");
        if (a == null) { Http.json(ex, 400, Map.of("error", "缺少 address")); return; }
        try {
            byte[] pk = chain.pubkeyOf(a);
            if (pk == null) { Http.json(ex, 404, Map.of("address", a, "found", false)); return; }
            Http.json(ex, 200, Map.of("address", a, "found", true, "pubkey", Sha3.toHex(pk)));
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
        m.put("signer", MlDsa87.source());
        Http.json(ex, 200, m);
    }

    // ── 节点间接口 ────────────────────────────────────────────────

    private void frame(HttpExchange ex) throws Exception {
        if (!post(ex)) return;
        String from = Http.query(ex).getOrDefault("from", "");
        FramePacket p = FrameCodec.decodeData(Http.body(ex));
        Ack a = node.onFrame(from, p);
        if (a == null) Http.bin(ex, 409, new byte[0]);
        else Http.bin(ex, 200, FrameCodec.encodeAck(a));
    }

    private void pull(HttpExchange ex) throws Exception {
        Map<String, String> q = Http.query(ex);
        long from = Long.parseLong(q.getOrDefault("from", "1"));
        int max = Math.min(1024, Integer.parseInt(q.getOrDefault("max", "256")));
        Http.bin(ex, 200, FrameCodec.encodeList(node.pull(from, max)));
    }

    private void internalSubmit(HttpExchange ex) throws Exception {
        if (!post(ex)) return;
        QccCanonicalReader r = new QccCanonicalReader(Http.body(ex));
        byte[] op = r.bytes(), sig = r.bytes();
        r.finish();
        SubmitResult res = node.submit(op, sig);
        Http.json(ex, httpCode(res), resultJson(res));
    }

    // ── 工具 ──────────────────────────────────────────────────────

    interface Handler { void handle(HttpExchange ex) throws Exception; }

    private void route(String path, Handler h) {
        server.createContext(path, ex -> {
            try {
                h.handle(ex);
            } catch (IllegalArgumentException | IllegalStateException e) {
                Http.json(ex, 400, Map.of("status", "DROPPED", "message", String.valueOf(e.getMessage())));
            } catch (Exception e) {
                Http.json(ex, 500, Map.of("error", e.getClass().getSimpleName() + ": " + e.getMessage()));
            }
        });
    }

    private Handler internal(Handler h) {
        return ex -> {
            InetAddress from = ex.getRemoteAddress().getAddress();
            if (!from.isLoopbackAddress() && !internalAllowed.contains(from)) {
                Http.json(ex, 403, Map.of("error", "节点间接口只对节点开放"));
                return;
            }
            h.handle(ex);
        };
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

    private static SSLContext sslContext(String path, String pass) throws Exception {
        KeyStore ks = KeyStore.getInstance(path.endsWith(".jks") ? "JKS" : "PKCS12");
        try (FileInputStream in = new FileInputStream(path)) { ks.load(in, pass.toCharArray()); }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, pass.toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        return ctx;
    }
}
