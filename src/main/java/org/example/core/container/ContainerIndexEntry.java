package org.example.core.container;


public class ContainerIndexEntry {
    public int height;        // 区块高度
    public long offset;       // 区块在容器中的 byte offset
    public int length;        // 区块大小
    public byte[] blockHash;  // 16或32字节
}

