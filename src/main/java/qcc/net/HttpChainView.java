package qcc.name.chain;

import qcc.name.core.PledgeFact;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * HttpChainView —— 通过 QCC 的 HTTP API 读取链上事实。
 *
 * 同一个类覆盖两种部署:
 *   独立部署  baseUrl 指向远程节点
 *   同机部署  baseUrl 指向 http://127.0.0.1:9080
 * 不做 TCP 直连 9951 那个版本 —— 那要把 QCC 的 UniversalFrame/QccTcpConfig
 * 拉进 classpath,两个项目就耦合了,namespace 也就没法独立开源和 fork。
 * 本机多一跳 HTTP 在 namespace 这个量级上完全无感。
 *
 * ═══ 响应结构(取自真实探测)═══════════════════════════════════════
 *
 * GET /v1/tag/{tagName}
 *   {"ok":true,"found":true,"data":{
 *      "tagName":"qccos","owner":"QMnGE…","credentialHash":"fc8e982b…",
 *      "regTime":1788412538307,"transferTime":0,
 *      "gasPolicy":true,"governance":true,"version":"1.0.0"}}
 *   → credentialHash 就是 TagRule 的注册交易 hash,用作 namespace 的 instanceId
 *
 * GET /v1/pledge/{address}?tag=&hash=&assetId=&minAmount=
 *   {"ok":true,"kind":"pledge","data":"{\"address\":…,\"qualified\":false,\"exists\":false}"}
 *   注意 data 是**被转义过的 JSON 字符串**,必须两层解析。
 *   直接对整个响应体做 contains("\"qualified\":true") 永远匹配不上,
 *   因为转义后的反斜杠让字符序列对不齐 —— PledgeAuthorizedTest 踩过这个坑。
 *
 * ═══ 两处已知缺口(标注出来,不假装解决了)═══════════════════════
 *
 *  (A) exists=true 时 data 里有没有 assetId / amount,尚未取得样本。
 *      所以门槛判断暂时依赖服务端返回的 qualified —— 但 minAmount 和
 *      assetId 是本类从**协议参数**里带过去的,链只负责比较,规则仍然
 *      由协议决定,这一点没有让步。拿到样本后改成本地判断。
 *
 *  (B) 没有"取当前最新高度"的接口。currentHeight() 目前用指数+二分探测,
 *      是临时手段:每次调用 O(log n) 次请求,而且高度增长时会有抖动。
 *      正式实现需要 QCC 侧提供 /v1/height 之类的端点。
 */
public final class HttpChainView implements ChainView {

    private final String baseUrl;
    private final String assetId;
    private final long   minAmount;
    private final HttpClient http;
    private volatile HeightTracker tracker;

    /**
     * @param assetId   协议 params.pledgeAssetId
     * @param minAmount 协议 params.pledgeMinAmount —— 规则来自协议,不是硬编码
     */
    public HttpChainView(String baseUrl, String assetId, long minAmount) {
        this.baseUrl   = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.assetId   = assetId;
        this.minAmount = minAmount;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    }

    // ── 授权质押三要素 ────────────────────────────────────────────

    @Override
    public PledgeFact authPledge(String address, String tag, String credentialHash) {
        String url = baseUrl + "/v1/pledge/" + enc(address)
                + "?tag=" + enc(tag)
                + "&hash=" + enc(credentialHash)
                + "&assetId=" + enc(assetId)
                + "&minAmount=" + minAmount;
        String body = get(url);
        if (body == null) return PledgeFact.none();

        String data = unescapedField(body, "data");
        if (data == null) return PledgeFact.none();

        boolean exists    = boolField(data, "exists");
        boolean qualified = boolField(data, "qualified");
        if (!exists) return PledgeFact.none();

        // 缺口 (A):优先用响应里的真实金额;没有就用 qualified 回退。
        // 回退时把 amount 记成 minAmount(刚好达标),这样 PledgeFact.satisfies
        // 的语义仍然自洽,不会把"达标"错记成"超额很多"。
        Long amount = longField(data, "amount");
        String asset = strField(data, "assetId");
        if (amount == null) amount = qualified ? minAmount : 0L;
        if (asset == null)  asset  = assetId;
        return new PledgeFact(true, asset, amount);
    }

    // ── tag 归属 → instanceId ─────────────────────────────────────

    public record TagFact(String tagName, String owner, String credentialHash, long regTime) {}

    /** namespace 实例的 instanceId 取根 tag 的 TagRule 交易 hash。 */
    public TagFact tag(String tagName) {
        String body = get(baseUrl + "/v1/tag/" + enc(tagName));
        if (body == null || !boolField(body, "found")) return null;
        return new TagFact(
                strField(body, "tagName"),
                strField(body, "owner"),
                strField(body, "credentialHash"),
                longOr(longField(body, "regTime"), 0L));
    }

    @Override
    public byte[] pubkeyOf(String address) {
        // 待接:AddressKeyVault 对应的 HTTP 端点。
        // 批量验签走这里,现在返回 null 让调用方走 SKIP 模式并在报告里标注。
        return null;
    }

    // ── 当前高度(临时实现)─────────────────────────────────────

    /**
     * 缺口 (B):QCC 没有"取当前高度"的端点(hash 查询给的是某笔交易所在的
     * 高度,不是链头)。交给 HeightTracker:冷启动定位一次,之后后台试探
     * h+1 前进,摊薄 O(1) 且单调不减。
     *
     * 首次调用会做一次冷启动定位,所以启动阶段应显式调 startHeightTracking()。
     */
    @Override
    public long currentHeight() {
        HeightTracker t = tracker;
        if (t == null) t = startHeightTracking(3000);
        return t.current();
    }

    /** 启动高度跟踪。pollIntervalMs 建议取出块间隔的一半。 */
    public synchronized HeightTracker startHeightTracking(long pollIntervalMs) {
        if (tracker == null) {
            HeightTracker t = new HeightTracker(baseUrl, pollIntervalMs);
            t.start();
            tracker = t;
        }
        return tracker;
    }

    public void stopHeightTracking() {
        HeightTracker t = tracker;
        if (t != null) { t.close(); tracker = null; }
    }

    // ── HTTP ──────────────────────────────────────────────────────

    private String get(String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(15))
                    .header("Accept", "application/json")
                    .GET().build();
            HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString());
            return r.statusCode() == 200 ? r.body() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String enc(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }

    // ── 宽容的字段提取 ────────────────────────────────────────────
    //
    // 这里**故意不用 StrictJson**。StrictJson 是给引导协议用的,它拒绝
    // 重复 key、拒绝 null、拒绝小数 —— 因为协议是信任根,任何歧义都不能容忍。
    // 网络响应是另一回事:字段会增删,可能有 null,不该因为多了个字段就崩。
    // 两种解析器对应两种信任级别,不要混用。

    /** 取出 "data":"...(转义的 JSON)..." 并反转义。 */
    private static String unescapedField(String body, String field) {
        String raw = strField(body, field);
        if (raw == null) return null;
        return raw.replace("\\\"", "\"").replace("\\\\", "\\");
    }

    private static String strField(String s, String field) {
        String k = "\"" + field + "\":\"";
        int i = s.indexOf(k);
        if (i < 0) return null;
        int p = i + k.length();
        StringBuilder b = new StringBuilder();
        while (p < s.length()) {
            char c = s.charAt(p);
            if (c == '\\' && p + 1 < s.length()) { b.append(c).append(s.charAt(p + 1)); p += 2; continue; }
            if (c == '"') break;
            b.append(c); p++;
        }
        return b.toString();
    }

    private static boolean boolField(String s, String field) {
        int i = s.indexOf("\"" + field + "\":");
        if (i < 0) return false;
        int p = i + field.length() + 3;
        while (p < s.length() && (s.charAt(p) == ' ')) p++;
        return s.startsWith("true", p);
    }

    private static Long longField(String s, String field) {
        int i = s.indexOf("\"" + field + "\":");
        if (i < 0) return null;
        int p = i + field.length() + 3;
        while (p < s.length() && s.charAt(p) == ' ') p++;
        int st = p;
        if (p < s.length() && s.charAt(p) == '-') p++;
        while (p < s.length() && Character.isDigit(s.charAt(p))) p++;
        if (p == st) return null;
        try { return Long.parseLong(s.substring(st, p)); }
        catch (NumberFormatException e) { return null; }
    }

    private static long longOr(Long v, long d) { return v == null ? d : v; }
}
