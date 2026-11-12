package qcc.name.node;

import qcc.name.chain.ChainView;
import qcc.name.protocol.NameProtocol;

import java.nio.file.Path;
import java.util.List;
import java.util.function.LongSupplier;

/**
 * 节点配置。
 *   order      核心节点序号表（创世固定），term 的主节点 = order[term mod N]，初始主节点为 order[0]
 *   observers  冗余节点：只同步与查询，不参与确认与接班
 * wallClock 只用于入口层的时间窗检查，不进入确定性核心。
 */
public record NodeConfig(String nodeId, Path dataDir, List<String> order, List<String> observers, NameProtocol protocol,
                         String instanceId, ChainView chain, Transport transport, LongSupplier wallClock) {

    public NodeConfig {
        order = List.copyOf(order);
        observers = List.copyOf(observers);
        if (!order.contains(nodeId) && !observers.contains(nodeId))
            throw new IllegalArgumentException(nodeId + " 不在 nodes / observers 中");
    }

    /** 兼容：无冗余节点。 */
    public NodeConfig(String nodeId, Path dataDir, List<String> order, NameProtocol protocol,
                      String instanceId, ChainView chain, Transport transport, LongSupplier wallClock) {
        this(nodeId, dataDir, order, List.of(), protocol, instanceId, chain, transport, wallClock);
    }
}
