package qcc.name.node;

import qcc.name.frame.Ack;
import qcc.name.frame.FramePacket;
import qcc.name.frame.Heartbeat;

import java.util.List;
import java.util.Map;

/**
 * 节点间通信。本地模拟用 InMemoryTransport；部署时用 HttpTransport（AES-256-GCM）。
 * 所有方法在对端不可达时返回 null（不抛异常），由调用方决定后续。
 * 对端按 nodeId 寻址，地址来自成员表（updatePeers）；只有加入集群前联系 seeds 时按 URL 寻址。
 */
public interface Transport {

    /** 非主节点把用户请求透传给主节点。 */
    SubmitResult forwardSubmit(String targetNodeId, byte[] opBytes, byte[] signature, byte[] pubkey);

    /** 主节点推送一帧，返回对端的 ACK；对端拒绝或不可达返回 null。 */
    Ack pushFrame(String fromNodeId, String targetNodeId, FramePacket packet);

    /** 从对端拉取 [fromSeq, fromSeq+max) 的帧。 */
    List<FramePacket> pull(String targetNodeId, long fromSeq, int max);

    Heartbeat heartbeat(String targetNodeId);

    /** 集群消息（hello / announce / vote，JSON）。 */
    byte[] cluster(String targetNodeId, byte[] json);

    /** 按地址发集群消息：加入集群前联系 seeds 用。 */
    byte[] clusterAt(String baseUrl, byte[] json);

    /** 成员表变化时更新 nodeId → URL。 */
    default void updatePeers(Map<String, String> idToUrl) { }
}
