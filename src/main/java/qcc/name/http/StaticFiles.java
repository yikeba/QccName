package qcc.name.http;

import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * 静态网站（Flutter Web / HTML）。直接读 webDir 下的文件，改网页无需重启节点。
 *   - 路径中不含 "." 且文件不存在 → 返回 index.html（SPA 路由回退）
 *   - 拒绝 ".." 越界访问；只读，不列目录
 *   - /v1/、/internal/、/admin/ 由节点接口处理，不会进到这里
 */
final class StaticFiles {

    private final Path root;

    private static final Map<String, String> TYPES = Map.ofEntries(
            Map.entry("html", "text/html; charset=utf-8"), Map.entry("htm", "text/html; charset=utf-8"),
            Map.entry("js", "text/javascript; charset=utf-8"), Map.entry("mjs", "text/javascript; charset=utf-8"),
            Map.entry("css", "text/css; charset=utf-8"), Map.entry("json", "application/json; charset=utf-8"),
            Map.entry("txt", "text/plain; charset=utf-8"), Map.entry("md", "text/markdown; charset=utf-8"),
            Map.entry("xml", "application/xml"), Map.entry("wasm", "application/wasm"),
            Map.entry("png", "image/png"), Map.entry("jpg", "image/jpeg"), Map.entry("jpeg", "image/jpeg"),
            Map.entry("gif", "image/gif"), Map.entry("svg", "image/svg+xml"), Map.entry("ico", "image/x-icon"),
            Map.entry("webp", "image/webp"), Map.entry("woff", "font/woff"), Map.entry("woff2", "font/woff2"),
            Map.entry("ttf", "font/ttf"), Map.entry("otf", "font/otf"), Map.entry("pdf", "application/pdf"),
            Map.entry("mp4", "video/mp4"), Map.entry("webm", "video/webm"));

    StaticFiles(Path root) { this.root = root.toAbsolutePath().normalize(); }

    void handle(HttpExchange ex) throws IOException {
        String m = ex.getRequestMethod();
        if (!m.equals("GET") && !m.equals("HEAD")) { Http.send(ex, 405, "text/plain", new byte[0]); return; }
        if (!Files.isDirectory(root)) {
            Http.send(ex, 404, "text/plain; charset=utf-8",
                    ("网站目录不存在：" + root + "（创建该目录并放入 index.html 即可，无需重启）").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return;
        }
        String path = ex.getRequestURI().getPath();
        if (path == null || path.isEmpty() || path.equals("/")) path = "/index.html";
        Path f = root.resolve(path.substring(1)).normalize();
        if (!f.startsWith(root)) { Http.send(ex, 403, "text/plain", new byte[0]); return; }
        if (Files.isDirectory(f)) f = f.resolve("index.html");
        if (!Files.isRegularFile(f)) {
            String last = path.substring(path.lastIndexOf('/') + 1);
            Path index = root.resolve("index.html");
            if (!last.contains(".") && Files.isRegularFile(index)) f = index;     // SPA 路由回退
            else { Http.send(ex, 404, "text/plain; charset=utf-8", "404".getBytes()); return; }
        }
        String name = f.getFileName().toString();
        String ext = name.contains(".") ? name.substring(name.lastIndexOf('.') + 1).toLowerCase() : "";
        long len = Files.size(f);
        ex.getResponseHeaders().set("Content-Type", TYPES.getOrDefault(ext, "application/octet-stream"));
        // index.html 不缓存（发版即生效）；其余资源短缓存
        ex.getResponseHeaders().set("Cache-Control", name.equals("index.html") ? "no-cache" : "public, max-age=300");
        if (m.equals("HEAD")) { ex.sendResponseHeaders(200, -1); ex.close(); return; }
        ex.sendResponseHeaders(200, len == 0 ? -1 : len);
        if (len > 0) try (OutputStream os = ex.getResponseBody()) { Files.copy(f, os); }
        ex.close();
    }
}