package qcc.name.chain;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

/**
 * HeightTracker —— 维护一个单调不减的链头高度指针。
 *
 * ═══ 为什么不直接问链头 ═══════════════════════════════════════════
 * QCC 目前没有"取当前高度"的端点。hash 查询返回的是**那笔交易所在的高度**,
 * 不是链头 —— 两回事,修好 hash 查询也补不上。
 *
 * ═══ 为什么不需要精确的链头 ═══════════════════════════════════════
 * admitHeight 的唯一作用是让防重放检查可重放(见 OpInput 的说明)。
 * 它不需要精确等于链头,只需要满足三条:
 *   1. 是 leader 真实观察到过的高度(不能凭空编)
 *   2. 单调不减(否则同一 epoch 内会出现时间倒流)
 *   3. 不超过 epoch header 的 endBlockHeight(交叉约束,防 leader 撒谎)
 * 落后几个容器完全无害 —— 防重放窗口是 100 个区块,留足了余量。
 *
 * ═══ 做法 ═════════════════════════════════════════════════════════
 * 冷启动:指数上探 + 二分,一次性定位(约 2·log₂H 次请求)。
 * 之后:后台按固定间隔试探 h+1,存在就前进。摊薄开销 O(1),
 * 而且单调性由构造保证 —— 只会往前走,永远不会回退。
 *
 * 这样比每次调用都二分好两个数量级,也不需要 QCC 侧加端点。
 * 如果以后有了 /v1/height,把 advance() 换成一次直接查询即可,其余不变。
 */
public final class HeightTracker implements AutoCloseable {

    private final String baseUrl;
    private final HttpClient http;
    private final AtomicLong height = new AtomicLong(0);
    private final long pollIntervalMs;
    private volatile boolean running = true;
    private Thread poller;

    public HeightTracker(String baseUrl, long pollIntervalMs) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.pollIntervalMs = pollIntervalMs;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    }

    /** 冷启动定位 + 启动后台推进。返回定位到的初始高度。 */
    public long start() {
        long h = bootstrap();
        height.set(h);
        poller = new Thread(this::pollLoop, "qccname-height");
        poller.setDaemon(true);
        poller.start();
        return h;
    }

    /**
     * 当前高度。**永不回退** —— 即使链回滚或节点换了一个落后的,
     * 这里返回的值也只会停住不动,不会变小。
     * 时间倒流会让同一个 epoch 内的 admitHeight 非单调,进而让
     * "admitHeight <= endBlockHeight" 这条交叉约束失效。
     */
    public long current() { return height.get(); }

    /** 手动推进一步,单元测试和无后台线程的场景用。 */
    public long advance() {
        long h = height.get();
        while (exists(h + 1)) h = height.incrementAndGet();
        return h;
    }

    private void pollLoop() {
        while (running) {
            try {
                advance();
                Thread.sleep(pollIntervalMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception ignored) {
                // 链暂时不可达不算错误:高度停住,namespace 继续用旧值。
                // 防重放窗口 100 个区块,短暂落后不影响正确性。
            }
        }
    }

    @Override
    public void close() {
        running = false;
        if (poller != null) poller.interrupt();
    }

    // ── 冷启动:指数上探 + 二分 ───────────────────────────────────

    private long bootstrap() {
        if (!exists(1)) return 0;
        long lo = 1, hi = 2;
        while (exists(hi)) {
            lo = hi;
            hi <<= 1;
            if (hi > (1L << 40)) break;   // 防御:高度不可能到 10^12
        }
        while (lo + 1 < hi) {
            long mid = lo + (hi - lo) / 2;
            if (exists(mid)) lo = mid; else hi = mid;
        }
        return lo;
    }

    private boolean exists(long h) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/v1/containerHeight/" + h))
                    .timeout(Duration.ofSeconds(10))
                    .header("Accept", "application/json")
                    .GET().build();
            HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) return false;
            String b = r.body();
            // 存在的容器返回 {"ok":true,...};不存在时 ok=false 或结构不同
            int i = b.indexOf("\"ok\":");
            return i >= 0 && b.startsWith("true", i + 5);
        } catch (Exception e) {
            return false;
        }
    }
}
