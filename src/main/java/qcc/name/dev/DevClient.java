package qcc.name.dev;

import qcc.name.chain.HttpChainView;
import qcc.name.codec.Sha3;
import qcc.name.config.QccNameConfig;
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
 *   importkey <label> <地址> <授权质押hash> <私钥文件>
 *                                   导入测试链上的真实地址（私钥文件内容为 hex：BC/liboqs 原始私钥）
 *   pledge <label>                  到链上查该用户的授权质押（三要素）
 *   newuser <label> [质押QCC=1]     【仅开发链】生成密钥与地址，登记公钥，建授权质押
 *   register <label> <name>         注册，例 register alice alice.qcc
 *   unregister <label> <name>       删除（regSeq 先通过 verify 取得）
 *   verify <name> [label]           验证，并用 L1 证据对照开发链独立核对
 *   revoke <label>                  授权方撤销质押
 *   status                          节点状态
 *
 * 开发链（chains 第一项）、密钥目录取自 QccNameConfig。默认发往 seeds 第一个节点（seeds 为空时发往本机 port）；
 * 末尾加 @序号（seeds 中第 n 个）或 @IP:端口 指定节点，例：verify alice.qcc alice @45.92.158.123:9180
 */
public final class DevClient {

    static final HttpClient HTTP = HttpClient.newHttpClient();
    static final QccNameConfig CFG = QccNameConfig.load();
    static String NODE = CFG.clientNodeUrl();
    static final String CHAIN = CFG.chains.get(0);
    static final Path KEYS = CFG.devKeys;

    public static void main(String[] a) throws Exception {
        if (a.length == 0) { usage(); return; }
        if (a[a.length - 1].startsWith("@")) {                     // 末尾 @序号（seeds 中第 n 个）或 @IP:端口
            String t = a[a.length - 1].substring(1);
            NODE = t.matches("\\d+") ? CFG.seeds.get(Integer.parseInt(t)) : qcc.name.node.Cluster.parseAddr(t).url();
            a = java.util.Arrays.copyOf(a, a.length - 1);
        }
        NameProtocol p = ProtocolLoader.loadFile(CFG.protocolFile, null);
        System.out.println("→ " + NODE);
        switch (a[0]) {
            case "newuser"    -> newUser(p, a[1], a.length > 2 ? Long.parseLong(a[2]) : 1);
            case "importkey"  -> importKey(a[1], a[2], a[3], Path.of(a[4]));
            case "pledge"     -> pledge(p, a[1]);
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

    static void importKey(String label, String address, String cred, Path privFile) throws Exception {
        String priv = Files.readString(privFile).trim();
        Sha3.fromHex(priv);                                  // 校验是 hex
        Properties pr = new Properties();
        pr.setProperty("label", label);
        pr.setProperty("address", address);
        pr.setProperty("credentialHash", cred.toLowerCase(java.util.Locale.ROOT));
        pr.setProperty("priv", priv);
        pr.setProperty("signer", MlDsa87.source());
        Files.createDirectories(KEYS);
        try (OutputStream os = Files.newOutputStream(KEYS.resolve(label + ".properties"))) { pr.store(os, "qccname dev user (imported)"); }
        System.out.println("已导入 " + label + "  地址 " + address + "  → " + KEYS.resolve(label + ".properties"));
        System.out.println("  链上公钥：" + (new HttpChainView(CHAIN).pubkeyOf(address) != null ? "存在" : "查不到（该地址未在链上出现过）"));
    }

    static void pledge(NameProtocol p, String label) throws Exception {
        Properties u = load(label);
        var f = new HttpChainView(CHAIN).authPledge(u.getProperty("address"), p.pledgeTag, u.getProperty("credentialHash"));
        System.out.println(u.getProperty("address") + " tag=" + p.pledgeTag + " → exists=" + f.exists()
                + (f.exists() ? " " + f.amount() + " " + f.assetId() + " from=" + f.from() : ""));
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
        if (Boolean.TRUE.equals(v.get("reserved"))) {
            System.out.println("保留名：结论来自 Reserved 表（链上交易 " + v.get("reservedTx") + "），核对 GET /v1/hash/{tx} 的 from / 高度 / payload");
            return;
        }
        if (address.isEmpty()) address = StrictJson.str(v, "address");
        Map<String, Object> ev = StrictJson.obj(v, "evidence");
        VerifyResult r = new VerifyResult(VerifyResult.Status.MATCH, name, address, StrictJson.num(v, "regSeq"),
                StrictJson.str(v, "credentialHash"), StrictJson.num(v, "asOf"), (int) StrictJson.num(v, "term"),
                StrictJson.str(v, "nodeId"), Base64.getDecoder().decode(StrictJson.str(ev, "opBytes")),
                Sha3.fromHex(StrictJson.str(ev, "sig")),
                ev.get("pubkey") instanceof String pk ? Sha3.fromHex(pk) : null);
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
        System.out.println("用法: DevClient importkey <label> <地址> <质押hash> <私钥文件> | pledge <label> | register <label> <name>"
                + " | unregister <label> <name> | verify <name> [label] | status | newuser/revoke（仅开发链）  末尾 @序号 指定节点");
    }
}
