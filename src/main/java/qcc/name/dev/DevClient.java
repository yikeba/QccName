package qcc.name.dev;

import qcc.name.chain.HttpChainView;
import qcc.name.codec.Sha3;
import qcc.name.crypto.MlDsa87;
import qcc.name.http.Json;
import qcc.name.node.VerifyResult;
import qcc.name.op.NameOp;
import qcc.name.op.RegisterOp;
import qcc.name.op.UnregisterOp;
import qcc.name.protocol.NameProtocol;
import qcc.name.protocol.ProtocolLoader;
import qcc.name.protocol.StrictJson;
import qcc.name.verify.ResultVerifier;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

/**
 * 开发客户端：扮演钱包，对开发链和 namespace 节点发请求。
 *
 *   newuser <label> [质押QCC=1]     生成密钥与地址，登记公钥，建授权质押（tag=协议 pledgeTag）
 *   register <label> <name>         注册，例 register alice alice.qcc
 *   unregister <label> <name>       删除（regSeq 先通过 verify 取得）
 *   verify <name> [label]           验证，并用 L1 证据对照开发链独立核对
 *   revoke <label>                  授权方撤销质押
 *   status                          节点状态
 *
 *   -Dqccname.node=http://127.0.0.1:9180   请求发往哪个节点（发到备节点会透传给主节点）
 *   -Dqccname.chain=http://127.0.0.1:9190  开发链
 *   -Dqccname.devKeys=~/qccname-dev        用户密钥保存目录（开发用，私钥明文保存）
 */
public final class DevClient {

    static final HttpClient HTTP = HttpClient.newHttpClient();
    static final String NODE  = System.getProperty("qccname.node", "http://127.0.0.1:9180");
    static final String CHAIN = System.getProperty("qccname.chain", "http://127.0.0.1:9190");
    static final Path KEYS = Path.of(System.getProperty("qccname.devKeys",
            Path.of(System.getProperty("user.home"), "qccname-dev").toString()));

    public static void main(String[] a) throws Exception {
        if (a.length == 0) { usage(); return; }
        NameProtocol p = ProtocolLoader.loadFile(Path.of(System.getProperty("qccname.protocol", "qcc-name-v1.0.0.json")), null);
        switch (a[0]) {
            case "newuser"    -> newUser(p, a[1], a.length > 2 ? Long.parseLong(a[2]) : 1);
            case "register"   -> register(p, a[1], a[2]);
            case "unregister" -> unregister(p, a[1], a[2]);
            case "verify"     -> verify(p, a[1], a.length > 2 ? load(a[2]).getProperty("address") : "");
            case "revoke"     -> revoke(p, a[1]);
            case "status"     -> System.out.println(get(NODE + "/v1/status"));
            default           -> usage();
        }
    }

    static void newUser(NameProtocol p, String label, long qcc) throws Exception {
        MlDsa87.Keys k = MlDsa87.generate();
        String alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        SecureRandom r = new SecureRandom();
        StringBuilder addr = new StringBuilder("Q");
        for (int i = 0; i < 33; i++) addr.append(alphabet.charAt(r.nextInt(alphabet.length())));
        post(CHAIN + "/dev/user", Map.of("address", addr.toString(), "pubkey", Sha3.toHex(k.pub())));
        Map<String, Object> pl = new LinkedHashMap<>();
        pl.put("to", addr.toString());
        pl.put("amount", qcc * 1_000_000_000L);
        pl.put("tag", p.pledgeTag);
        pl.put("from", "QDevAssetWallet" + label);
        String hash = StrictJson.str(StrictJson.parseObject(post(CHAIN + "/dev/pledge", pl).getBytes(StandardCharsets.UTF_8)), "hash");
        Properties pr = new Properties();
        pr.setProperty("label", label);
        pr.setProperty("address", addr.toString());
        pr.setProperty("credentialHash", hash);
        pr.setProperty("pub", Sha3.toHex(k.pub()));
        pr.setProperty("priv", Sha3.toHex(k.priv()));
        pr.setProperty("signer", MlDsa87.source());
        Files.createDirectories(KEYS);
        try (OutputStream os = Files.newOutputStream(KEYS.resolve(label + ".properties"))) { pr.store(os, "qccname dev user"); }
        System.out.println("用户 " + label + "  地址 " + addr + "\n  授权质押 " + qcc + " QCC  credentialHash=" + hash
                + "\n  密钥保存在 " + KEYS.resolve(label + ".properties"));
    }

    static void register(NameProtocol p, String label, String name) throws Exception {
        Properties u = load(label);
        RegisterOp op = new RegisterOp(p.chain, u.getProperty("address"), name, System.currentTimeMillis(), u.getProperty("credentialHash"));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("chain", op.chain);
        body.put("address", op.address);
        body.put("name", op.name);
        body.put("timestamp", op.timestamp);
        body.put("credentialHash", op.credentialHash);
        body.put("sig", sign(u, op));
        System.out.println("签名字符串 " + op.toSign());
        System.out.println(post(NODE + "/v1/register", body));
    }

    static void unregister(NameProtocol p, String label, String name) throws Exception {
        Properties u = load(label);
        Map<String, Object> v = StrictJson.parseObject(get(NODE + "/v1/verify?name=" + enc(name) + "&address=" + enc(u.getProperty("address")))
                .getBytes(StandardCharsets.UTF_8));
        if (!StrictJson.bool(v, "match")) { System.out.println(name + " 不属于 " + label + "：" + StrictJson.str(v, "status")); return; }
        UnregisterOp op = new UnregisterOp(p.chain, u.getProperty("address"), name, System.currentTimeMillis(), StrictJson.num(v, "regSeq"));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("chain", op.chain);
        body.put("address", op.address);
        body.put("name", op.name);
        body.put("timestamp", op.timestamp);
        body.put("regSeq", op.regSeq);
        body.put("sig", sign(u, op));
        System.out.println("签名字符串 " + op.toSign());
        System.out.println(post(NODE + "/v1/unregister", body));
    }

    static void verify(NameProtocol p, String name, String address) throws Exception {
        String resp = get(NODE + "/v1/verify?name=" + enc(name) + "&address=" + enc(address));
        System.out.println(resp);
        Map<String, Object> v = StrictJson.parseObject(resp.getBytes(StandardCharsets.UTF_8));
        if (!v.containsKey("evidence")) return;
        if (address.isEmpty()) address = StrictJson.str(v, "address");
        Map<String, Object> ev = StrictJson.obj(v, "evidence");
        VerifyResult r = new VerifyResult(VerifyResult.Status.MATCH, name, address, StrictJson.num(v, "regSeq"),
                StrictJson.str(v, "credentialHash"), StrictJson.num(v, "asOf"), (int) StrictJson.num(v, "term"),
                StrictJson.str(v, "nodeId"), Base64.getDecoder().decode(StrictJson.str(ev, "opBytes")),
                Sha3.fromHex(StrictJson.str(ev, "sig")));
        System.out.println("L1 独立核对（只信开发链，不信节点）：");
        ResultVerifier.Report rep = ResultVerifier.check(r, p, new HttpChainView(CHAIN));
        rep.lines().forEach(l -> System.out.println("  " + l));
        System.out.println(rep.ok() ? "  → 结果可信" : "  → 结果不可信");
    }

    static void revoke(NameProtocol p, String label) throws Exception {
        Properties u = load(label);
        System.out.println(post(CHAIN + "/dev/revoke", Map.of("to", u.getProperty("address"), "hash", u.getProperty("credentialHash"), "tag", p.pledgeTag)));
    }

    // ── 工具 ──────────────────────────────────────────────────────

    static String sign(Properties u, NameOp op) {
        return Sha3.toHex(MlDsa87.sign(Sha3.fromHex(u.getProperty("priv")), op.signBytes()));
    }

    static Properties load(String label) throws IOException {
        Path f = KEYS.resolve(label + ".properties");
        if (!Files.exists(f)) throw new IllegalArgumentException("没有用户 " + label + "，先执行 newuser " + label);
        Properties p = new Properties();
        try (InputStream in = Files.newInputStream(f)) { p.load(in); }
        if (!MlDsa87.source().equals(p.getProperty("signer")))
            System.err.println("⚠ 该用户的私钥由 " + p.getProperty("signer") + " 生成，当前是 " + MlDsa87.source() + "，私钥编码可能不兼容");
        return p;
    }

    static String post(String url, Object body) throws Exception {
        HttpResponse<String> r = HTTP.send(HttpRequest.newBuilder(URI.create(url)).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(Json.write(body))).build(), HttpResponse.BodyHandlers.ofString());
        return r.body();
    }

    static String get(String url) throws Exception {
        return HTTP.send(HttpRequest.newBuilder(URI.create(url)).GET().build(), HttpResponse.BodyHandlers.ofString()).body();
    }

    static String enc(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }

    static void usage() {
        System.out.println("用法: DevClient newuser <label> [QCC] | register <label> <name> | unregister <label> <name>"
                + " | verify <name> [label] | revoke <label> | status");
    }
}
