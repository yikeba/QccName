package org.que.protocol;

import org.que.core.block.BlockService;
import org.que.core.container.ContainerService;
import org.que.core.queData.QubeDataBaseFactory;
import org.que.core.queData.QueBaseData;

import java.nio.charset.StandardCharsets;

public class QubePacketHandler {

    public static String handle(QubePacket packet) {

        // 1. 验签
        if (!packet.verify()) {
            return "{\"error\": \"invalid signature\"}";
        }
        // 3. 三大对象还原
        String json = new String(packet.payload, StandardCharsets.UTF_8);
        QueBaseData data = QubeDataBaseFactory.fromJson(json);


        // 4. 写入区块（你的 BlockService）
        long blockHeight = BlockService.addData(data);

        // 5. 写入容器（你的 ContainerService）
        String containerInfo = ContainerService.tryFlush();

        // 6. 返回结果
        return "{ \"status\": \"accepted\", " +
                "\"dataId\": \"" + data.getId() + "\"," +
                "\"blockHeight\": " + blockHeight + "," +
                "\"container\": \"" + containerInfo + "\" }";
    }
}

