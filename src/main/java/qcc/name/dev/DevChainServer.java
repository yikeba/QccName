package qcc.name.dev;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import qcc.name.chain.MockChainView;
import qcc.name.config.QccNameConfig;
import qcc.name.chain.PledgeFact;
import qcc.name.codec.Sha3;
import qcc.name.http.Json;
import qcc.name.protocol.StrictJson;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * 开发用模拟公链（内存，重启即清空）。只实现 namespace 用到的两个 QCC 接口，
 * 响应格式与测试链实测一致，节点直接用 HttpChainView 访问，不需要改任何代码：
 *
 *   GET /v1/pledge/{address}?tag=&hash=   {"ok":true,"kind":"pledge","data":"<转义 JSON>"}
 *   GET /v1/addresskey/{address}          QAKG 二进制
 *
 * 另有开发接口（真实链上对应钱包里的操作）：
 *   POST /dev/user    {"address","pubkey"}              登记地址公钥
 *   POST /dev/pledge  {"to","amount"[,"assetId","tag","from"]}  建一笔授权质押，返回 {"hash"}
 *   POST /dev/revoke  {"to","hash"[,"tag"]}             发起方撤销授权
 *
 * 只在不连测试链时使用：把配置中 chains 的第一项改成 http://127.0.0.1:9190。直接运行，无需参数。
 */
public final class DevChainServer {

    private final MockChainView chain = new MockChainView(System.currentTimeMillis());
    private final Map<String, Long> pubTimes = new TreeMap<>();
    private final SecureRandom rnd = new SecureRandom();

    public static void main(String[] args) throws Exception {
        int port = java.net.URI.create(QccNameConfig.load().chains.get(0)).getPort();
        if (port < 1) port = 9190;      // chain 指向测试链时，开发链仍用 9190
        new DevChainServer().start(port);
        System.out.println("开发链已启动 http://127.0.0.1:" + port + "  （内存数据，重启清空）");
    }

    public HttpServer start(int port) throws IOException {
        HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 64);
        s.createContext("/v1/pledge/", this::pledgeQuery);
        s.createContext("/v1/addresskey/", this::addressKey);
        s.createContext("/dev/user", this::devUser);
        s.createContext("/dev/pledge", this::devPledge);
        s.createContext("/dev/revoke", this::devRevoke);
        s.start();
        return s;
    }

    private void pledgeQuery(HttpExchange ex) throws IOException {
        String address = tail(ex, "/v1/pledge/");
        Map<String, String> q = query(ex);
        String tag = q.getOrDefault("tag", ""), hash = q.getOrDefault("hash", "");
        PledgeFact f = chain.authPledge(address, tag, hash);
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("address", address);
        d.put("tag", tag);
        d.put("hash", hash);
        d.put("exists", f.exists());
        if (f.exists()) {
            d.put("assetId", f.assetId());
            d.put("amount", f.amount());
            d.put("from", f.from());
            d.put("regTime", chain.now());
        }
        d.put("qualified", f.exists());
        Map<String, Object> outer = new LinkedHashMap<>();
        outer.put("ok", true);
        outer.put("kind", "pledge");
        outer.put("data", Json.write(d));          // 与 PledgeContext 一致：data 是转义后的 JSON 字符串
        send(ex, 200, "application/json", Json.write(outer).getBytes(StandardCharsets.UTF_8));
    }

    private void addressKey(HttpExchange ex) throws IOException {
        String address = tail(ex, "/v1/addresskey/");
        byte[] pk = chain.pubkeyOf(address);
        if (pk == null) { send(ex, 404, "text/plain", new byte[0]); return; }
        byte[] a = address.getBytes(StandardCharsets.US_ASCII);
        byte[] hex = Sha3.toHex(pk).getBytes(StandardCharsets.US_ASCII);
        int len = 4 + 2 + a.length + 2 + hex.length + 8;
        ByteBuffer b = ByteBuffer.allocate(4 + len);
        b.putInt(len).put("QAKG".getBytes(StandardCharsets.US_ASCII))
         .putShort((short) a.length).put(a).putShort((short) hex.length).put(hex)
         .putLong(pubTimes.getOrDefault(address, 0L));
        send(ex, 200, "application/octet-stream", b.array());
    }

    private void devUser(HttpExchange ex) throws IOException {
        Map<String, Object> j = body(ex);
        String a = StrictJson.str(j, "address");
        chain.putPubkey(a, Sha3.fromHex(StrictJson.str(j, "pubkey")));
        synchronized (pubTimes) { pubTimes.put(a, System.currentTimeMillis()); }
        ok(ex, Map.of("address", a));
    }

    private void devPledge(HttpExchange ex) throws IOException {
        Map<String, Object> j = body(ex);
        byte[] h = new byte[32];
        rnd.nextBytes(h);
        String hash = Sha3.toHex(h);
        String to = StrictJson.str(j, "to");
        chain.lock(to, opt(j, "tag", "qccio"), hash, opt(j, "assetId", "QCC"), StrictJson.num(j, "amount"),
                opt(j, "from", "QDevAssetWallet"));
        System.out.println("  授权质押 to=" + to + " amount=" + StrictJson.num(j, "amount") + " hash=" + hash);
        ok(ex, Map.of("hash", hash));
    }

    private void devRevoke(HttpExchange ex) throws IOException {
        Map<String, Object> j = body(ex);
        chain.revoke(StrictJson.str(j, "to"), opt(j, "tag", "qccio"), StrictJson.str(j, "hash"));
        System.out.println("  撤销授权 to=" + StrictJson.str(j, "to"));
        ok(ex, Map.of("revoked", true));
    }

    // ── 工具 ──────────────────────────────────────────────────────

    private static String opt(Map<String, Object> j, String k, String d) { return j.containsKey(k) ? StrictJson.str(j, k) : d; }

    private static Map<String, Object> body(HttpExchange ex) throws IOException {
        return StrictJson.parseObject(ex.getRequestBody().readAllBytes());
    }

    private static String tail(HttpExchange ex, String prefix) {
        return URLDecoder.decode(ex.getRequestURI().getRawPath().substring(prefix.length()), StandardCharsets.UTF_8);
    }

    private static Map<String, String> query(HttpExchange ex) {
        Map<String, String> m = new TreeMap<>();
        String q = ex.getRequestURI().getRawQuery();
        if (q != null) for (String kv : q.split("&")) {
            int i = kv.indexOf('=');
            if (i > 0) m.put(kv.substring(0, i), URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8));
        }
        return m;
    }

    private static void ok(HttpExchange ex, Object o) throws IOException {
        send(ex, 200, "application/json", Json.write(o).getBytes(StandardCharsets.UTF_8));
    }

    private static void send(HttpExchange ex, int code, String type, byte[] body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", type);
        ex.sendResponseHeaders(code, body.length == 0 ? -1 : body.length);
        if (body.length > 0) try (OutputStream os = ex.getResponseBody()) { os.write(body); }
        ex.close();
    }
}
