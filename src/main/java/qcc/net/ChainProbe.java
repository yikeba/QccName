package qcc.name.chain;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * ChainProbe —— 探测 QCC 公链 API 的真实响应结构。
 *
 * namespace 依赖公链的四件事,每一件都要知道确切的字段名才能写解析:
 *   1. tag 归属       /v1/tag/{tagName}          → instanceId 的来源
 *   2. 授权质押三要素  /v1/pledge/{address}?...   → 运行时鉴权(当前状态)
 *   3. 交易按 hash 查  /v1/hash/{txHash}          → 重放验证(带高度)
 *   4. 当前容器高度    /v1/containerHeight/{h}    → 时间源
 *
 * 只依赖 JDK,不需要 fastjson2,可以单独跑。
 * 输出原样打印,不做解析 —— 目的就是看清楚真实结构。
 *
 * 运行:
 *   java qcc.name.chain.ChainProbe [baseUrl]
 * 默认 baseUrl = https://test.qccio.com
 */
public class ChainProbe {

    static final String DEFAULT_BASE = "https://test.qccio.com";

    // 已知的测试数据。
    // 三要素来自钱包"授权质押"页:被授权地址 + tag + 授权凭证 hash。
    // 注意 address 必须是**被授权地址**(空钱包),不是质押发起方 ——
    // AuthPledge 的 key 是 被授权地址|tag|credentialHash,填错就是 exists=false。
    static final String[] TAGS      = {"qccname", "qccos"};
    static final String PLEDGE_ADDR = "QecAmMRVAgEvMSAVxCo4zmK15VQEssd822";
    static final String PLEDGE_TX   = "7ee5f7b3543fae3e68c59599bdc9134e7637bcbcc6f9f538a980bc200fe39598";
    static final String PLEDGE_TAG  = "qccname";
    static final String ASSET       = "QCC";
    /** 之前那笔(发起方视角),留着做对照 —— 它应该 exists=false。 */
    static final String PLEDGER_ADDR = "QVPpr9N5LcqeB628SU3WWWLwaGBUVzKUZw";

    static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15)).build();

    static String base;

    public static void main(String[] args) {
        base = args.length > 0 ? args[0] : DEFAULT_BASE;
        System.out.println("baseUrl = " + base);

        // ── 1. tag 归属 ───────────────────────────────────────────
        // namespace 实例的 instanceId 打算用根 tag 的 TagRule 交易 hash。
        // 这里要看清楚 data 里到底有没有 credentialHash / regTime。
        section("1. tag 归属  GET /v1/tag/{tagName}");
        String ownerQccname = null, ownerQccos = null;
        for (String tag : TAGS) {
            String body = get("/v1/tag/" + tag);
            show("tag=" + tag, body);
            String o = crudeField(body, "owner");
            if ("qccname".equals(tag)) ownerQccname = o; else ownerQccos = o;
        }
        System.out.println("\n  → qccname owner = " + ownerQccname);
        System.out.println("  → qccos   owner = " + ownerQccos);

        // ── 2. 授权质押三要素查询 ──────────────────────────────────
        // 这是 namespace 运行时鉴权唯一依赖的接口(对应 hasAuthPledge)。
        // 关键要看清:data 里有没有 assetId 和 amount。
        // PledgeFact 需要这两个才能做门槛判断,只有 exists/qualified 是不够的
        // —— 因为门槛 minAmount 是 namespace 自己从协议里读的,不能让链替我们判。
        section("2. 授权质押三要素  GET /v1/pledge/{address}");

        show("2a 三要素,不带门槛",
             get("/v1/pledge/" + PLEDGE_ADDR + "?tag=" + PLEDGE_TAG + "&hash=" + PLEDGE_TX));

        show("2b 三要素 + assetId",
             get("/v1/pledge/" + PLEDGE_ADDR + "?tag=" + PLEDGE_TAG + "&hash=" + PLEDGE_TX
                 + "&assetId=" + ASSET));

        // 门槛扫描 —— 用来同时确认两件事:
        //   (a) amount 的单位。2e 的明细里同时出现了 1000/20 和 40000000000000,
        //       前两个若按 NanoQCC 解释就是 0.000001 QCC,不可能是真实意图;
        //       所以客户端很可能在按整数 QCC 传,而创世锁按 NanoQCC 存。
        //       qualified 在哪一档翻转,单位就定了。
        //   (b) 比较是 >= 还是 >。差一个数,要么谁都过不了,要么门槛形同虚设。
        for (long min : new long[]{
                1L, 99L, 100L, 101L,
                1_000_000_000L, 99_000_000_000L, 100_000_000_000L, 100_000_000_001L}) {
            show("2c minAmount=" + min + "  (" + (min / 1_000_000_000.0) + " QCC)",
                 get("/v1/pledge/" + PLEDGE_ADDR + "?tag=" + PLEDGE_TAG + "&hash=" + PLEDGE_TX
                     + "&assetId=" + ASSET + "&minAmount=" + min));
        }

        // 隔离性:tag 换成 qccos,同一个 hash 应该查不到
        show("2d 错配 tag=qccos + qccname 的 hash(应 exists=false)",
             get("/v1/pledge/" + PLEDGE_ADDR + "?tag=qccos&hash=" + PLEDGE_TX
                 + "&assetId=" + ASSET));

        // 对照:用**质押发起方**的地址查同一 tag —— 应 exists=false,
        // 因为 AuthPledge 记的是被授权地址,不是发起方。
        show("2d2 用发起方地址查(应 exists=false)",
             get("/v1/pledge/" + PLEDGER_ADDR + "?tag=" + PLEDGE_TAG + "&hash=" + PLEDGE_TX
                 + "&assetId=" + ASSET));

        // 只有 address —— 已确认返回的是 pledgeStore(普通质押明细),
        // 不是 authPledgeStore。两个存储、两条路径。
        show("2e 仅 address(pledgeStore 明细)", get("/v1/pledge/" + PLEDGE_ADDR));

        // PledgeContext 里有个 type 参数还没试过。如果它能按地址列出
        // 授权质押,就能直接找到被授权地址,不用人工翻交易。
        for (String t : new String[]{"auth", "authorized", "AuthorizedPledge", "node", "all"}) {
            show("2f type=" + t, get("/v1/pledge/" + PLEDGE_ADDR + "?type=" + t));
        }

        // 如果已知被授权地址,用 -DauthAddr=... 传进来做三要素查询。
        // 这是拿到 exists=true 样本的最直接办法 —— 需要它才能确认
        // data 里到底有没有 assetId 和 amount。
        String authAddr = System.getProperty("authAddr");
        if (authAddr != null && !authAddr.isEmpty()) {
            show("2g 被授权地址三要素 " + authAddr,
                 get("/v1/pledge/" + authAddr + "?tag=" + PLEDGE_TAG + "&hash=" + PLEDGE_TX
                     + "&assetId=" + ASSET + "&minAmount=1"));
        } else {
            System.out.println("\n  ⚠ 未提供 -DauthAddr=<被授权地址>,跳过 exists=true 的样本采集");
        }

        // ── 3. 交易按 hash 查(重放验证的数据源)────────────────────
        // 需要的是:交易内容(能取出质押金额/资产/tag)+ 容器高度。
        // FailureHashVault 未 init 的话这里会报 IllegalStateException。
        section("3. 交易按 hash 查  GET /v1/hash/{txHash}");
        show("3a 质押交易", get("/v1/hash/" + PLEDGE_TX));

        // ── 4. 当前容器高度(时间源)────────────────────────────────
        // namespace 的 blockHeight / admitHeight 全部来自这里。
        // 需要一个"取当前高度"的接口;containerHeight/{n} 是按高度取内容,
        // 如果没有 /v1/height 之类的,就得从别处拿。
        section("4. 高度  GET /v1/containerHeight/{h}");
        String h = get("/v1/containerHeight/342665");
        show("4a 已知高度 342665(截断显示)", truncate(h, 600));
        System.out.println("\n  ⚠ 需要确认:有没有\"取当前最新高度\"的接口?");
        System.out.println("     namespace 的 admitHeight 每条操作都要用,不能靠猜。");

        // ── 5. 地址公钥(批量验签的来源)──────────────────────────
        // ContainerSignVerify 用的是 /v1/addresskey 作为 base,单条走
        // AddressKeyVaultDown.downAddress(base, address)。这里探清楚:
        //   (a) 单条的确切路径形态
        //   (b) wire 是裸 hex 还是 JSON 包装(ML-DSA-87 公钥 2592 字节 = 5184 hex 字符)
        //   (c) 有没有段式全量接口 —— 重放时必须走全量,不能逐条拉
        section("5. 地址公钥  /v1/addresskey");
        String addr = "QMnGE6bPBkvE6M2Dp28V8sTXo8bs5nTHy4";   // qccname 的质押发起方
        for (String path : new String[]{
                "/v1/addresskey/" + addr,
                "/v1/addresskey?address=" + addr,
                "/v1/addresskey/count",
                "/v1/addresskey/size/0"}) {
            show(path, truncate(get(path), 300));
        }

        section("完成");
        System.out.println("请把以上输出整份贴回,我据此把 HttpChainView 的解析写死。");
    }

    // ── 工具 ──────────────────────────────────────────────────────

    static String get(String path) {
        String url = base + path;
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(20))
                    .header("Accept", "application/json")
                    .GET().build();
            HttpResponse<String> resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
            return "[HTTP " + resp.statusCode() + "] " + resp.body();
        } catch (Exception e) {
            return "[请求失败] " + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    static void section(String title) {
        System.out.println();
        System.out.println("═".repeat(72));
        System.out.println("  " + title);
        System.out.println("═".repeat(72));
    }

    static void show(String label, String body) {
        System.out.println();
        System.out.println("── " + label);
        System.out.println(body);
    }

    /**
     * 极简字段提取,只为在探测阶段把 owner 拎出来打印。
     * 正式解析绝不用这种字符串匹配 —— data 字段是转义过的嵌套 JSON,
     * 必须两层解析(PledgeAuthorizedTest 的 isQualified 已经踩过这个坑)。
     */
    static String crudeField(String body, String field) {
        String key = "\"" + field + "\":\"";
        int i = body.indexOf(key);
        if (i < 0) return null;
        int s = i + key.length();
        int e = body.indexOf('"', s);
        return e < 0 ? null : body.substring(s, e);
    }

    static String truncate(String s, int n) {
        return s == null || s.length() <= n ? s : s.substring(0, n) + " …(共 " + s.length() + " 字符)";
    }
}
