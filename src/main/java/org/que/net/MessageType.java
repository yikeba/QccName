package org.que.net;


public enum MessageType {
    // 0x01: 心跳消息 (Heartbeat) - 节点健康状态的定期报告
    HEARTBEAT((byte) 0x01),

    // 0x02: 状态同步消息 (Status Sync) - 包含最新的区块高度和领导者信息
    STATUS_SYNC((byte) 0x02),

    // 0x03: 共识命令 (Consensus Command) - 例如：提议新区块、开始容器生成
    CONSENSUS_CMD((byte) 0x03),

    // 0x04: 错误/拒绝消息 (Error/Reject)
    ERROR((byte) 0x04);

    private final byte code;

    MessageType(byte code) {
        this.code = code;
    }

    public byte getCode() {
        return code;
    }

    public static MessageType fromCode(byte code) {
        for (MessageType type : MessageType.values()) {
            if (type.code == code) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown MessageType code: " + code);
    }
}