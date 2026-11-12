package qcc.name.chain;

import qcc.name.codec.Sha3;
import qcc.name.protocol.StrictJson;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 通过 QCC 公链 HTTP API 读取链上事实。只依赖 JDK。
 * ═══ GET /v1/pledge/{address}?tag=&hash=&assetId=&minAmount=0（已实测）═══
 *   命中  {"ok":true,"kind":"pledge","data":"{\"address\":…,\"exists\":true,\"assetId\":\"QCC\",
 *          \"amount\":1000000000,\"from\":…,\"regTime\":…,\"qualified\":true,…}"}
 *   未命中 data 里 exists=false
 *   失败  {"ok":true,"data":"error"}（PledgeContext 吞掉异常后的返回）→ ChainUnavailableException
 *   门槛不交给服务端判断：minAmount=0，金额在本地按协议 TagPolicy 比较。
 * ═══ GET /v1/addresskey/{address}（已实测，二进制）═══════════════════
 *   u32 len | "QAKG" | u16 addrLen | addr | u16 hexLen | hex(5184) | 8 字节
 *   【假设】末尾 8 字节含义未确认（推测为时间戳或高度），这里不使用。
 * ═══ chainTime ═══════════════════════════════════════════════════
 *   【假设，需确认】目前没有"最新容器时间戳"的接口，暂用本机墙钟并保证单调不减。
 *   chainTime 由主节点写进帧，备节点与回放者不重新获取，所以这里换实现不影响已写入的帧。
 */
public final class HttpChainView implements ChainView {

    private final String base;
    private final HttpClient http;
    private final AtomicLong lastTime = new AtomicLong();

    public HttpChainView(String baseUrl) {
        this.base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    }

    @Override
    public PledgeFact authPledge(String address, String tag, String credentialHash) {
        String url = base + "/v1/pledge/" + enc(address) + "?tag=" + enc(tag) + "&hash=" + enc(credentialHash)
                + "&minAmount=0";
        byte[] body = get(url);
        if (body == null) throw new ChainUnavailableException("pledge 查询无响应: " + address);
        return parsePledge(body);
    }

    static PledgeFact parsePledge(byte[] body) {
        try {
            Map<String, Object> outer = StrictJson.parseObject(body);
            if (!StrictJson.bool(outer, "ok")) throw new ChainUnavailableException("pledge ok=false");
            String data = StrictJson.str(outer, "data");
            if ("error".equals(data)) throw new ChainUnavailableException("pledge 服务端返回 error");
            Map<String, Object> d = StrictJson.parseObject(data.getBytes(StandardCharsets.UTF_8));
            if (!StrictJson.bool(d, "exists")) return PledgeFact.none();
            return new PledgeFact(true, StrictJson.str(d, "assetId"), StrictJson.num(d, "amount"),
                    StrictJson.str(d, "from"));
        } catch (ChainUnavailableException e) {
            throw e;
        } catch (RuntimeException e) {
            // 结构不符宁可报不可用，也不猜：猜成"无质押"会误拒，猜成"有质押"会白送名额
            throw new ChainUnavailableException("pledge 响应结构不符", e);
        }
    }

    @Override
    public byte[] pubkeyOf(String address) {
        byte[] body = get(base + "/v1/addresskey/" + enc(address));
        if (body == null || body.length == 0) return null;                 // 404 / 空：链上确实没有
        byte[] k = parseAddressKey(body, address);
        // 200 但不是 QAKG 格式（节点繁忙时返回的错误文本等）：视为暂时不可用，而不是"地址无公钥"
        if (k == null) throw new ChainUnavailableException("addresskey 响应格式不符（" + body.length + " 字节）: " + address);
        return k;
    }

    static byte[] parseAddressKey(byte[] b, String expectAddress) {
        try {
            ByteBuffer buf = ByteBuffer.wrap(b);
            int len = buf.getInt();
            if (len != b.length - 4) return null;
            byte[] magic = new byte[4];
            buf.get(magic);
            if (!"QAKG".equals(new String(magic, StandardCharsets.US_ASCII))) return null;
            byte[] addr = new byte[buf.getShort() & 0xFFFF];
            buf.get(addr);
            if (!expectAddress.equals(new String(addr, StandardCharsets.US_ASCII))) return null;
            byte[] hex = new byte[buf.getShort() & 0xFFFF];
            buf.get(hex);
            byte[] raw = Sha3.fromHex(new String(hex, StandardCharsets.US_ASCII));
            return raw.length == 2592 ? raw : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * GET /v1/hash/{txHash}（已实测）
     *   命中   {"ok":true,"kind":"TX","status":"SUCCESS","data":"{\"tx\":…,\"height\":…,\"confirmTimestamp\":…}"}
     *   查不到 {"ok":false,"error":"transaction not found: <txHash>"} → null
     *   其他 ok=false / 结构不符 → ChainUnavailableException（稍后重试，不当成"没有"）
     */
    @Override
    public ChainTx tx(String txHash) {
        byte[] body = get(base + "/v1/hash/" + enc(txHash));
        if (body == null || body.length == 0) return null;
        try {
            Map<String, Object> outer = StrictJson.parseObject(body);
            // 查不到（已实测）：{"ok":false,"error":"transaction not found: <txHash>"}
            if (!StrictJson.bool(outer, "ok")) {
                Object e = outer.get("error");
                if (e instanceof String err && err.startsWith("transaction not found")) return null;
                throw new ChainUnavailableException("交易查询失败: " + txHash + "：" + e);
            }
            return ChainTx.parse(txHash, body);
        } catch (RuntimeException e) {
            throw new ChainUnavailableException("交易响应结构不符: " + txHash + "：" + e.getMessage(), e);
        }
    }

    @Override
    public long chainTime() {
        long now = System.currentTimeMillis();
        return lastTime.updateAndGet(prev -> Math.max(prev, now));
    }

    private byte[] get(String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(15)).GET().build();
            HttpResponse<byte[]> r = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
            if (r.statusCode() == 404) return new byte[0];
            if (r.statusCode() != 200) throw new ChainUnavailableException("HTTP " + r.statusCode() + " " + url);
            return r.body();
        } catch (ChainUnavailableException e) {
            throw e;
        } catch (Exception e) {
            throw new ChainUnavailableException("链请求失败: " + url, e);
        }
    }

    private static String enc(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }
}