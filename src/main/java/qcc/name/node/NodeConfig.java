package qcc.name.node;

import qcc.name.chain.ChainView;
import qcc.name.protocol.NameProtocol;

import java.nio.file.Path;
import java.util.List;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * 节点配置。
 *
 * 两种启动方式：
 *   P2P（生产）  order 为空。seeds 为空 → 创世节点（第一台，本机即主节点）；
 *                seeds 非空 → 连接任意一个 seed 取得成员表后加入。重启时直接用本地 cluster.json。
 *   静态（测试） order 非空：首次启动时成员表 = order（第一个为主）+ observers。
 *
 *   selfAddr  本机公告地址（每次心跳取最新值，IPv6 地址轮换会自动更新到成员表）；进程内模拟可为 null
 *   selfCore  本机是否核心节点（公网 IPv4 → 核心；只有 IPv6 / NAT → 冗余）
 * wallClock 只用于入口层时间窗与故障检测，不进入确定性核心。
 */
public record NodeConfig(String nodeId, Path dataDir, List<String> order, List<String> observers, NameProtocol protocol,
                         String instanceId, ChainView chain, Transport transport, LongSupplier wallClock,
                         List<String> seeds, Supplier<Cluster.Addr> selfAddr, boolean selfCore) {

    public NodeConfig {
        order = List.copyOf(order);
        observers = List.copyOf(observers);
        seeds = List.copyOf(seeds);
        if (selfAddr == null) selfAddr = () -> null;
        if (!order.isEmpty() && !order.contains(nodeId) && !observers.contains(nodeId))
            throw new IllegalArgumentException(nodeId + " 不在 order / observers 中");
    }

    /** 静态成员表（测试）：含冗余节点。 */
    public NodeConfig(String nodeId, Path dataDir, List<String> order, List<String> observers, NameProtocol protocol,
                      String instanceId, ChainView chain, Transport transport, LongSupplier wallClock) {
        this(nodeId, dataDir, order, observers, protocol, instanceId, chain, transport, wallClock,
                List.of(), null, order.contains(nodeId));
    }

    /** 静态成员表（测试）：无冗余节点。 */
    public NodeConfig(String nodeId, Path dataDir, List<String> order, NameProtocol protocol,
                      String instanceId, ChainView chain, Transport transport, LongSupplier wallClock) {
        this(nodeId, dataDir, order, List.of(), protocol, instanceId, chain, transport, wallClock);
    }

    /** P2P 启动（生产）。 */
    public static NodeConfig p2p(String nodeId, Path dataDir, NameProtocol protocol, String instanceId, ChainView chain,
                                 Transport transport, List<String> seeds, Supplier<Cluster.Addr> selfAddr, boolean selfCore) {
        return new NodeConfig(nodeId, dataDir, List.of(), List.of(), protocol, instanceId, chain, transport,
                System::currentTimeMillis, seeds, selfAddr, selfCore);
    }
}
