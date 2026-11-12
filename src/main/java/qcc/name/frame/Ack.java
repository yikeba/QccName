package qcc.name.frame;

/** 备节点落盘确认。主节点只认 execHash 与自己一致的 ACK。 */
public record Ack(String nodeId, int term, long seq, byte[] execHash) {}
