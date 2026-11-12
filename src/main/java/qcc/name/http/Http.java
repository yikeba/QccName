package qcc.name.http;

import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeMap;

/** HttpExchange 的小工具：读请求体、解析查询串、写响应。 */
final class Http {
    static final int MAX_BODY = 8 * 1024 * 1024;

    private Http() {}

    static byte[] body(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            byte[] b = in.readNBytes(MAX_BODY + 1);
            if (b.length > MAX_BODY) throw new IOException("请求体过大");
            return b;
        }
    }

    static Map<String, String> query(HttpExchange ex) {
        Map<String, String> m = new TreeMap<>();
        String q = ex.getRequestURI().getRawQuery();
        if (q == null || q.isEmpty()) return m;
        for (String kv : q.split("&")) {
            int i = kv.indexOf('=');
            String k = i < 0 ? kv : kv.substring(0, i);
            String v = i < 0 ? "" : kv.substring(i + 1);
            m.put(URLDecoder.decode(k, StandardCharsets.UTF_8), URLDecoder.decode(v, StandardCharsets.UTF_8));
        }
        return m;
    }

    static void json(HttpExchange ex, int code, Object body) throws IOException {
        send(ex, code, "application/json; charset=utf-8", Json.write(body).getBytes(StandardCharsets.UTF_8));
    }

    static void bin(HttpExchange ex, int code, byte[] body) throws IOException {
        send(ex, code, "application/octet-stream", body);
    }

    static void send(HttpExchange ex, int code, String type, byte[] body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", type);
        ex.sendResponseHeaders(code, body.length == 0 ? -1 : body.length);
        if (body.length > 0) try (OutputStream os = ex.getResponseBody()) { os.write(body); }
        ex.close();
    }
}
