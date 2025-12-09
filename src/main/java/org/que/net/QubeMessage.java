package org.que.net;

import java.io.Serializable;

public class QubeMessage implements Serializable {

    // Magic Number: 假设为 0xDEADBEEF
    public static final int MAGIC_NUMBER = 0xDEADBEEF;
    public static final byte VERSION = 0x01;

    private final MessageType type;
    private final byte[] data;

    public QubeMessage(MessageType type, byte[] data) {
        this.type = type;
        this.data = data;
    }

    // Getters...
    public MessageType getType() {
        return type;
    }

    public byte[] getData() {
        return data;
    }
    // ...
}
