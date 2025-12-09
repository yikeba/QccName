package org.que.net;


import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.LengthFieldBasedFrameDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.util.CharsetUtil;
import org.que.service.NodeHealthStatus;

import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class QubeChainP2PClient {

    private final String host;
    private final int port;
    private final int nodeId;
    private Channel channel;
    private final NioEventLoopGroup workerGroup = new NioEventLoopGroup();

    public QubeChainP2PClient(String host, int port, int nodeId) {
        this.host = host;
        this.port = port;
        this.nodeId = nodeId;
    }

    public void start() {
        try {
            Bootstrap b = new Bootstrap();
            b.group(workerGroup)
                    .channel(NioSocketChannel.class)
                    .option(ChannelOption.TCP_NODELAY, true)
                    .handler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        public void initChannel(SocketChannel ch) {
                            ChannelPipeline p = ch.pipeline();

                            // 1. 基于长度字段的解码器 (与服务器保持一致)
                            p.addLast(new LengthFieldBasedFrameDecoder(
                                    65535, 0, 4, 0, 4
                            ));

                            // 2. 字符串编解码器 (处理 JSON 字符串)
                            p.addLast(new StringDecoder(CharsetUtil.UTF_8));
                            p.addLast(new StringEncoder(CharsetUtil.UTF_8));

                            // 3. 客户端消息处理器
                            p.addLast(new ClientConsensusHandler(nodeId));
                        }
                    });

            // 建立连接
            ChannelFuture future = b.connect(host, port).sync();
            this.channel = future.channel();
            System.out.println("Node " + nodeId + " connected to Balancer at " + host + ":" + port);

            // 启动定时心跳任务
            scheduleHeartbeat();

            this.channel.closeFuture().sync(); // 阻塞直到连接关闭

        } catch (Exception e) {
            System.err.println("Node " + nodeId + " connection failed: " + e.getMessage());
        } finally {
            workerGroup.shutdownGracefully();
        }
    }

    private void scheduleHeartbeat() {
        // 使用 Netty 的 EventLoopGroup 来调度任务
        workerGroup.scheduleAtFixedRate(() -> {
            if (channel != null && channel.isActive()) {
                // 模拟获取本地健康状态和最新区块高度
                long currentBlockHeight = (long) (Math.random() * 1000);
                NodeHealthStatus status = new NodeHealthStatus(nodeId, NodeHealthStatus.HealthStatus.HEALTHY);
                status.updateStatus(currentBlockHeight);

                // 模拟 JSON 消息封装 (user:command:data)
                String jsonHeartbeat = createHeartbeatJson(status);

                // 发送心跳包
                channel.writeAndFlush(jsonHeartbeat);
                System.out.println("Node " + nodeId + " sent HEARTBEAT: " + currentBlockHeight);
            }
        }, 5, 5, TimeUnit.SECONDS); // 每 5 秒发送一次
    }

    // 模拟 JSON 封装：将健康状态封装成符合协议的 JSON 字符串
    private String createHeartbeatJson(NodeHealthStatus status) {
        // 实际应用中，您应该使用 Jackson/Gson 将 NodeHealthStatus 序列化为 JSON
        // 这里我们使用一个简化的格式来模拟 user:command:data 结构
        String dataJson = status.toString(); // 假设 NodeHealthStatus.toString() 已经返回 JSON

        return "{" +
                "\"user\":\"Node-" + nodeId + "\"," +
                "\"command\":\"HEARTBEAT\"," +
                "\"data\":\"" + dataJson + "\"" +
                "}";
    }

    public void stop() {
        if (channel != null) {
            channel.close();
        }
        workerGroup.shutdownGracefully();
    }

    // ==================== 客户端消息处理器 ====================
    private static class ClientConsensusHandler extends SimpleChannelInboundHandler<String> {
        private final int nodeId;

        public ClientConsensusHandler(int nodeId) {
            this.nodeId = nodeId;
        }

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, String msg) {
            System.out.println("Node " + nodeId + " received CMD: " + msg);
            // TODO: 在这里解析 JSON 消息，判断 command 是否为 CONSENSUS_CMD，然后执行相应的任务。
            // 例如：如果是 CONSENSUS_CMD，则启动容器生成区块。
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            cause.printStackTrace();
            ctx.close();
        }
    }

    public static void main(String[] args) {
        // 假设节点平衡集群运行在 localhost:8080
        new QubeChainP2PClient("127.0.0.1", 8080, 101).start();
        new QubeChainP2PClient("127.0.0.1", 8080, 102).start();
    }
}