package org.example.core.container;

public class ContainerFooter {

    public static final int FIXED_SIZE = 64;

    public String magicEnd = "QEND";  // 容器尾标识
    public long indexOffset;          // 冗余
    public long indexLength;          // 冗余

    public byte[] containerHash;      // 容器最终哈希（计算整个容器）
}