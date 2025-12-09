package org.que.net;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import com.fasterxml.jackson.databind.ObjectMapper; // ⚠️ 需要 Jackson 依赖

import java.util.HashMap;
import java.util.Map;

public class ClientHeartbeatHandler extends SimpleChannelInboundHandler<String> {

    private final ObjectMapper mapper = new ObjectMapper();
    private final String serverId;

    public ClientHeartbeatHandler(String serverId) {
        this.serverId = serverId;
    }

    /**
     * 辅助方法：构建 JSON 消息字符串
     */
    private String buildJsonMessage(String command, Map<String, Object> data) throws Exception {
        Map<String, Object> message = new HashMap<>();
        message.put("command", command);
        if (data != null && !data.isEmpty()) {
            message.put("data", data);
        }
        return mapper.writeValueAsString(message);
    }

    /**
     * 核心逻辑：接收服务器端的 JSON 响应
     */
    @Override
    protected void channelRead0(ChannelHandlerContext ctx, String msg) throws Exception {
        // 1. 解析收到的 JSON 消息 (msg 是解压后的 JSON 字符串)
        Map<String, Object> receivedMsg = mapper.readValue(msg, Map.class);
        String command = (String) receivedMsg.get("command");

        System.out.printf("[Node %s] Received Response: %s%n", serverId, command);

        if ("HEARTBEAT_RESPONSE".equals(command)) {
            // 协议阶段 2/3：收到 Leader 的心跳响应

            // 可以在此提取 Leader 返回的 IP 地址等信息
            Map<String, Object> data = (Map<String, Object>) receivedMsg.get("data");
            System.out.printf("  > Leader Status: %s, My IP (confirmed): %s%n",
                    (String)data.get("status"), (String)data.get("ip"));

            // 协议阶段 3/3：发送心跳确认 ACK
            sendAcknowledge(ctx);
        }
        // TODO: 在这里处理 SCHEDULE_CONTAINER 等 Leader 发送的其他指令
    }

    /**
     * 利用 IdleStateHandler 的事件，定时发送心跳请求
     */
    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof IdleStateEvent e) {
            if (e.state() == IdleState.WRITER_IDLE) {
                // 写空闲触发，发送心跳请求 (协议阶段 1/3)
                sendHeartbeatRequest(ctx);
            }
        } else {
            super.userEventTriggered(ctx, evt);
        }
    }

    /**
     * 发送心跳请求 (协议阶段 1/3)
     */
    private void sendHeartbeatRequest(ChannelHandlerContext ctx) throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("serverId", serverId);
        data.put("timestamp", System.currentTimeMillis());
        // 报告节点状态 (例如：当前负载、是否准备就绪)
        data.put("nodeStatus", "READY_FOR_TASK");

        String requestJson = buildJsonMessage("HEARTBEAT_REQUEST", data);

        ctx.writeAndFlush(requestJson); // 消息被 JZlibEncoder 压缩发送
        System.out.printf("⬅️ [Node %s] Sent HEARTBEAT_REQUEST.%n", serverId);
    }

    /**
     * 发送心跳确认 (协议阶段 3/3)
     */
    private void sendAcknowledge(ChannelHandlerContext ctx) throws Exception {
        String ackJson = buildJsonMessage("HEARTBEAT_ACK", null);
        ctx.writeAndFlush(ackJson);
        System.out.printf("⬅️ [Node %s] Sent HEARTBEAT_ACK.%n", serverId);
    }

    // 异常处理
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        System.err.println("Client exception occurred, closing channel: " + cause.getMessage());
        ctx.close();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        System.out.println("Connection to Leader lost. Attempting to reconnect...");
        // ⚠️ 实际生产环境中，客户端应实现重连逻辑 (例如使用定时任务)
        super.channelInactive(ctx);
    }
}