package org.que.protocol;

import org.que.core.queBlock.BlockController;
import org.que.core.queData.QubeDataBaseFactory;
import org.que.core.queData.QueBaseData;

import java.nio.charset.StandardCharsets;

public class QubePacketHandler {

    /**
     * 返回给客户端的 JSON 内容格式：
     *
     * {
     *    "status": "accepted",
     *    "dataId": "...",
     *    "queueSize": 123
     * }
     *
     * 不再返回 blockHeight，因为区块是异步生成。
     */
    public static String handle(QubePacket packet) {

        // 1. 验证协议签名
        if (!packet.verify()) {
            return "{ \"status\": \"error\", \"message\": \"invalid signature\" }";
        }

        // 2. 解析 payload → 三大数据对象
        String json = new String(packet.payload, StandardCharsets.UTF_8);
        QueBaseData data = QubeDataBaseFactory.fromJson(json);

        // 3.（可选）设置手续费（当前测试网 fee=0）
        data.setFee(0L);

        // 4. 进入区块控制器队列（异步 3 秒出块）
        BlockController.receive(data);

        // 5. 返回立即响应（客户端无需等待出块）
        int q = BlockController.getQueueSize();
        return "{ \"status\": \"accepted\", " +
                "\"dataId\": \"" + data.getId() + "\"," +
                "\"queueSize\": " + q + " }";
    }
}
