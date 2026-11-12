package qcc.name.http;

import qcc.name.codec.QccCanonicalWriter;
import qcc.name.crypto.ClusterCipher;
import qcc.name.frame.Ack;
import qcc.name.frame.FrameCodec;
import qcc.name.frame.FramePacket;
import qcc.name.frame.Heartbeat;
import qcc.name.node.SubmitResult;
import qcc.name.node.Transport;
import qcc.name.protocol.StrictJson;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * 节点间通信：POST /internal/*，请求与响应均为 ClusterCipher（AES-256-GCM）密文。
 * 帧、ACK、心跳的明文仍是 FrameCodec 二进制线格式。对端不可达、拒绝或解密失败都返回 null，
 * 并打印原因（HTTP 状态码 / 解密失败），便于区分"网络不通"与"密钥或配置不一致"。
 */
public final class HttpTransport implements Transport {

    private final Map<String, String> peers = new java.util.concurrent.ConcurrentHashMap<>();   // nodeId → baseUrl
    private final ClusterCipher cipher;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    private static final Duration TIMEOUT = Duration.ofSeconds(10);
    private final Map<String, Long> lastWarn = new java.util.concurrent.ConcurrentHashMap<>();

    public HttpTransport(Map<String, String> peers, ClusterCipher cipher) {
        this.peers.putAll(peers);
        this.cipher = cipher;
    }

    @Override
    public SubmitResult forwardSubmit(String target, byte[] opBytes, byte[] sig, byte[] pubkey) {
        byte[] r = call(target, "/internal/submit", new QccCanonicalWriter(opBytes.length + sig.length + pubkey.length + 24)
                .bytes(opBytes).bytes(sig).bytes(pubkey).toBytes());
        if (r == null) return SubmitResult.unavailable("主节点 " + target + " 不可达");
        try { return NameHttpServer.parseResult(StrictJson.parseObject(r)); }
        catch (RuntimeException e) { return SubmitResult.unavailable("主节点响应无法解析"); }
    }

    @Override
    public Ack pushFrame(String from, String target, FramePacket p) {
        byte[] r = call(target, "/internal/frame", new QccCanonicalWriter(512).str(from).bytes(FrameCodec.encodeData(p)).toBytes());
        if (r == null || r.length == 0) return null;
        try { return FrameCodec.decodeAck(r); } catch (RuntimeException e) { return null; }
    }

    @Override
    public List<FramePacket> pull(String target, long fromSeq, int max) {
        byte[] r = call(target, "/internal/pull", new QccCanonicalWriter(16).u64(fromSeq).u32(max).toBytes());
        if (r == null) return null;
        try { return FrameCodec.decodeList(r); } catch (RuntimeException e) { return null; }
    }

    @Override
    public Heartbeat heartbeat(String target) {
        byte[] r = call(target, "/internal/heartbeat", new byte[0]);
        if (r == null) return null;
        try { return FrameCodec.decodeHeartbeat(r); } catch (RuntimeException e) { return null; }
    }

    @Override
    public byte[] cluster(String target, byte[] json) {
        byte[] r = call(target, "/internal/cluster", json);
        return r == null || r.length == 0 ? null : r;
    }

    @Override
    public byte[] clusterAt(String baseUrl, byte[] json) {
        byte[] r = callUrl(baseUrl, baseUrl, "/internal/cluster", json);
        return r == null || r.length == 0 ? null : r;
    }

    /** 成员表变化：合并更新（不删除静态配置的条目）。 */
    @Override
    public void updatePeers(Map<String, String> idToUrl) { peers.putAll(idToUrl); }

    /** 加密请求 → POST → 解密响应。200 返回明文；409 表示对端拒收，返回空数组；其余返回 null。 */
    private byte[] call(String target, String path, byte[] plain) {
        String base = peers.get(target);
        if (base == null) return null;
        return callUrl(target, base, path, plain);
    }

    private byte[] callUrl(String target, String base, String path, byte[] plain) {
        byte[][] sealed = cipher.sealRequest(path, plain);
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(base + path)).timeout(TIMEOUT)
                    .header("Content-Type", "application/octet-stream")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(sealed[0])).build();
            HttpResponse<byte[]> r = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
            if (r.statusCode() == 409) return new byte[0];
            if (r.statusCode() != 200) { warn(target, path + " → HTTP " + r.statusCode() + (r.statusCode() == 403 ? "（clusterKey 不一致或时钟偏差 >60s）" : "")); return null; }
            return cipher.openResponse(path, r.body(), sealed[1]);
        } catch (SecurityException e) {
            warn(target, path + " → 响应解密失败：" + e.getMessage());
            return null;
        } catch (Exception e) {
            warn(target, path + " → 连接失败：" + e.getClass().getSimpleName());
            return null;
        }
    }

    /** 同一对端同类问题每 30 秒最多打印一次。 */
    private void warn(String target, String msg) {
        long now = System.currentTimeMillis();
        String k = target + msg;
        Long last = lastWarn.get(k);
        if (last != null && now - last < 30_000) return;
        lastWarn.put(k, now);
        System.err.println("[net] " + shortId(target) + " " + peers.getOrDefault(target, "") + " " + msg);
    }

    private static String shortId(String id) { return id.length() > 10 ? id.substring(0, 10) + "…" : id; }
}
