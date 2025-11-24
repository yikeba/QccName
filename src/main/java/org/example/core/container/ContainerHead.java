package org.example.core.container;


public class ContainerHead {

    public static final int FIXED_SIZE = 256; // 固定头大小

    public String magic = "QUBE";      // 4 bytes
    public short version = 1;          // 协议版本
    public byte[] containerHash;       // 32 bytes（先为空，封存时写）
    public long baseTime;              // 用于短时间编码
    public int blockCount;             // 区块数量
    public long indexOffset;           // index 的起始位置
    public long indexLength;           // index 长度
    public String createTime;          // 容器创建时间（短时间戳）
    // 保留字段，填满到256字节
    public byte[] reserved = new byte[FIXED_SIZE - 4 - 2 - 32 - 8 - 4 - 8 - 8];

}
