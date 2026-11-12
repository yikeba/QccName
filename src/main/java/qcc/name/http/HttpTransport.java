package qcc.name.http;

import qcc.name.codec.QccCanonicalWriter;
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
 * 基于 HTTP 的节点间通信，对端是 NameHttpServer 的 /internal/* 接口。
 * 帧、ACK、心跳一律走 FrameCodec 二进制线格式。对端不可达返回 null。
 */
public final class HttpTransport implements Transport {

    private final Map<String, String> peers;   // nodeId → baseUrl
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    public HttpTransport(Map<String, String> peers) { this.peers = Map.copyOf(peers); }

    @Override
    public SubmitResult forwardSubmit(String target, byte[] opBytes, byte[] sig) {
        byte[] body = new QccCanonicalWriter(opBytes.length + sig.length + 16).bytes(opBytes).bytes(sig).toBytes();
        HttpResponse<byte[]> r = send(target, "/internal/submit", body);
        if (r == null) return SubmitResult.unavailable("主节点 " + target + " 不可达");
        try {
            return NameHttpServer.parseResult(StrictJson.parseObject(r.body()));
        } catch (RuntimeException e) {
            return SubmitResult.unavailable("主节点响应无法解析");
        }
    }

    @Override
    public Ack pushFrame(String from, String target, FramePacket p) {
        HttpResponse<byte[]> r = send(target, "/internal/frame?from=" + from, FrameCodec.encodeData(p));
        if (r == null || r.statusCode() != 200) return null;
        try { return FrameCodec.decodeAck(r.body()); } catch (RuntimeException e) { return null; }
    }

    @Override
    public List<FramePacket> pull(String target, long fromSeq, int max) {
        HttpResponse<byte[]> r = get(target, "/internal/pull?from=" + fromSeq + "&max=" + max);
        if (r == null || r.statusCode() != 200) return null;
        try { return FrameCodec.decodeList(r.body()); } catch (RuntimeException e) { return null; }
    }

    @Override
    public Heartbeat heartbeat(String target) {
        HttpResponse<byte[]> r = get(target, "/internal/heartbeat");
        if (r == null || r.statusCode() != 200) return null;
        try { return FrameCodec.decodeHeartbeat(r.body()); } catch (RuntimeException e) { return null; }
    }

    private HttpResponse<byte[]> send(String target, String path, byte[] body) {
        String base = peers.get(target);
        if (base == null) return null;
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(base + path)).timeout(TIMEOUT)
                    .header("Content-Type", "application/octet-stream")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build();
            return http.send(req, HttpResponse.BodyHandlers.ofByteArray());
        } catch (Exception e) {
            return null;
        }
    }

    private HttpResponse<byte[]> get(String target, String path) {
        String base = peers.get(target);
        if (base == null) return null;
        try {
            return http.send(HttpRequest.newBuilder(URI.create(base + path)).timeout(TIMEOUT).GET().build(),
                    HttpResponse.BodyHandlers.ofByteArray());
        } catch (Exception e) {
            return null;
        }
    }
}
