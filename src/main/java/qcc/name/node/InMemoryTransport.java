package qcc.name.node;

import qcc.name.frame.Ack;
import qcc.name.frame.FrameCodec;
import qcc.name.frame.FramePacket;
import qcc.name.frame.Heartbeat;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 进程内传输，用于本地模拟。每次传递都经过 FrameCodec 编解码，
 * 线格式与真实网络一致；可把节点标记为离线来模拟宕机与分区。
 */
public final class InMemoryTransport implements Transport {

    private final Map<String, NameNode> nodes = new ConcurrentHashMap<>();
    private final Set<String> down = ConcurrentHashMap.newKeySet();

    public void register(NameNode n)       { nodes.put(n.nodeId(), n); }
    public void setDown(String id, boolean d) { if (d) down.add(id); else down.remove(id); }
    public boolean isDown(String id)       { return down.contains(id) || !nodes.containsKey(id); }

    @Override
    public SubmitResult forwardSubmit(String target, byte[] opBytes, byte[] sig, byte[] pubkey) {
        if (isDown(target)) return SubmitResult.unavailable("主节点 " + target + " 不可达");
        return nodes.get(target).submit(opBytes, sig, pubkey);
    }

    @Override
    public Ack pushFrame(String from, String target, FramePacket p) {
        if (isDown(target) || isDown(from)) return null;
        FramePacket wire = FrameCodec.decodeData(FrameCodec.encodeData(p));
        Ack a = nodes.get(target).onFrame(from, wire);
        return a == null ? null : FrameCodec.decodeAck(FrameCodec.encodeAck(a));
    }

    @Override
    public List<FramePacket> pull(String target, long fromSeq, int max) {
        if (isDown(target)) return null;
        return FrameCodec.decodeList(FrameCodec.encodeList(nodes.get(target).pull(fromSeq, max)));
    }

    @Override
    public Heartbeat heartbeat(String target) {
        if (isDown(target)) return null;
        return FrameCodec.decodeHeartbeat(FrameCodec.encodeHeartbeat(nodes.get(target).heartbeat()));
    }

    @Override
    public byte[] cluster(String target, byte[] json) {
        if (isDown(target)) return null;
        try { return nodes.get(target).onCluster(json); } catch (RuntimeException e) { return null; }
    }

    /** 进程内地址写成 mem://nodeId。 */
    @Override
    public byte[] clusterAt(String url, byte[] json) {
        return url.startsWith("mem://") ? cluster(url.substring(6), json) : null;
    }
}
