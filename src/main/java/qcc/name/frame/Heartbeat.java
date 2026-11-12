package qcc.name.frame;

/** 心跳：节点用它互相比对 (term, seq, execHash)，不一致即告警。 */
public record Heartbeat(String nodeId, int term, long seq, byte[] execHash, boolean primary) {}
