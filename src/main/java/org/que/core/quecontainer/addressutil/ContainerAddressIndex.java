package org.que.core.quecontainer.addressutil;


import java.util.List;

public class ContainerAddressIndex {

    public int containerSeq;
    public List<String> hash160List;   // 地址 hash 列表（短）
    public byte[] compressed;          // LZ4 压缩数据（300~1500 bytes）
}