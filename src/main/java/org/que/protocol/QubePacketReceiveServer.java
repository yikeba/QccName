package org.que.protocol;

import com.alibaba.fastjson2.JSON;
import com.sun.net.httpserver.HttpServer;
import org.que.core.queBlock.BlockController;
import org.que.core.queData.QueBaseData;
import org.que.protocol.QubeDataProtocol;
import org.que.protocol.QubePacket;

import java.io.OutputStream;
import java.net.InetSocketAddress;

public class QubePacketReceiveServer {

    public static void start(int port) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/data/submit", exchange -> {
            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            try {
                // 读取 QubePacket JSON
                byte[] body = exchange.getRequestBody().readAllBytes();
                QubePacket packet = JSON.parseObject(body, QubePacket.class);

                // 解码 + 验签 + 生成地址
                QueBaseData data = QubeDataProtocol.decodeData(packet);

                // 投递给区块写入管道
                BlockController.receive(data);

                // 构建响应
                String resp = "{\"success\":true}";
                exchange.sendResponseHeaders(200, resp.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(resp.getBytes());
                }

            } catch (Exception e) {
                String resp = "{\"success\":false,\"error\":\"" + e.getMessage() + "\"}";
                exchange.sendResponseHeaders(500, resp.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(resp.getBytes());
                }
            }
        });

        server.start();
        System.out.println("🚀 QubePacketReceiveServer 已启动 http://localhost:" + port);
    }
}
