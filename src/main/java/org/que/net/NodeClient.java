package org.que.net;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.compression.Lz4FrameDecoder;
import io.netty.handler.codec.compression.Lz4FrameEncoder;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.util.CharsetUtil;

public class NodeClient {

    private final String host;
    private final int port;
    private final String serverId; // 节点的唯一标识

    public NodeClient(String host, int port, String serverId) {
        this.host = host;
        this.port = port;
        this.serverId = serverId;
    }

    public void run() throws Exception {
        EventLoopGroup group = new NioEventLoopGroup();
        try {
            Bootstrap b = new Bootstrap();
            b.group(group)
                    .channel(NioSocketChannel.class) // 客户端使用 NioSocketChannel
                    .option(ChannelOption.TCP_NODELAY, true)
                    .handler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        public void initChannel(SocketChannel ch) throws Exception {
                            ch.pipeline().addLast(
                                    // 1. 写空闲检测：每 5 秒触发一次写操作空闲事件
                                    new IdleStateHandler(0, 5, 0),
                                    // 2. 解压 (unzip)：处理来自服务器的压缩响应
                                    new Lz4FrameDecoder(),
                                    // 3. 压缩 (zip)：压缩发送给服务器的心跳请求
                                    new Lz4FrameEncoder(),
                                    // 4. 字符串解码：将解压后的字节流解码为 JSON 字符串
                                    new StringDecoder(CharsetUtil.UTF_8),
                                    // 5. 字符串编码：将 JSON 字符串编码为字节流 (发送前会被压缩)
                                    new StringEncoder(CharsetUtil.UTF_8),
                                    // 6. 核心业务处理器
                                    new ClientHeartbeatHandler(serverId)
                            );
                        }
                    });

            // 发起异步连接操作
            ChannelFuture f = b.connect(host, port).sync();
            System.out.printf("✅ Node Client %s connected to Leader at %s:%d%n", serverId, host, port);

            // 等待客户端链路关闭
            f.channel().closeFuture().sync();
        } finally {
            group.shutdownGracefully();
            System.out.println("Node Client shut down.");
        }
    }

    public static void main(String[] args) throws Exception {
        // Leader 服务器的地址和统一端口
        String leaderHost = "192.168.1.169";
        int leaderPort = 19999;

        // 节点服务器的唯一标识
        String nodeId = "Node-001";

        new NodeClient(leaderHost, leaderPort, nodeId).run();
    }
}