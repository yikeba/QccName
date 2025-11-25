// Container.java —— 纯粹的硬盘存储器（全球最硬冷数据版）
package org.example.core.container;


import org.example.core.block.QubeBlock;
import org.example.core.TimestampUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Container implements AutoCloseable {

    private ContainerHead head;
    private List<ContainerIndexEntry> indexList;
    private RandomAccessFile raf;
    private String filePath;
    private boolean isNew; // 是否是新建容器

    // ==================== 构建方式1：新建容器 ====================
    public Container(String filePath, long baseTime) {
        this.filePath = filePath;
        this.isNew = true;
        this.head = new ContainerHead();
        this.head.baseTime = baseTime;
        this.head.createTime = TimestampUtil.encode(System.currentTimeMillis());
        this.indexList = new ArrayList<>();

        try {
            this.raf = new RandomAccessFile(filePath, "rw");
            raf.write(new byte[ContainerHead.FIXED_SIZE]); // 占位写头
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException("创建容器文件失败: " + e.getMessage());
        }
    }

    // ==================== 构建方式2：读取已有文件 ====================
    public Container(String filePath) {
        this.filePath = filePath;
        this.isNew = false;
        this.indexList = new ArrayList<>();
        try {
            this.raf = new RandomAccessFile(filePath, "r");
            this.head = readHead(raf);
            this.indexList = readIndex(raf, head.indexOffset, head.indexLength);
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException("读取容器文件失败: " + e.getMessage());
        }
    }

    // ==================== 新建容器写入区块 ====================
    public void appendBlock(QubeBlock block, byte[] blockBytes) {
        if(!isNew) throw new IllegalStateException("只允许对新建容器写入区块");
        try {
            long offset = raf.getFilePointer();
            raf.writeInt(blockBytes.length);   // 区块长度
            raf.write(blockBytes);             // 区块数据

            ContainerIndexEntry entry = new ContainerIndexEntry();
            entry.height = block.getBlockNumber();
            entry.offset = offset;
            entry.length = blockBytes.length;
            entry.blockHash = block.getCurrentHash().getBytes();
            indexList.add(entry);

        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("写入区块失败：" + e.getMessage());
        }
    }

    // ==================== 封存容器 ====================
    public void close() {
        if(!isNew) return;
        try {
            // 写索引
            long indexOffset = raf.getFilePointer();
            for(ContainerIndexEntry e : indexList){
                writeIndexEntry(raf, e);
            }
            long indexLength = raf.getFilePointer() - indexOffset;

            // 写尾部
            byte[] containerHash = computeContainerHash();
            writeFooter(raf, indexOffset, indexLength, containerHash);

            // 回写头
            head.indexOffset = indexOffset;
            head.indexLength = indexLength;
            head.blockCount = indexList.size();
            head.containerHash = containerHash;

            raf.seek(0);
            writeHead(raf, head);

            raf.close();
            isNew = false;
        } catch(IOException e){
            e.printStackTrace();
            System.err.println("封存容器失败: " + e.getMessage());
        }
    }

    // ==================== 读取区块数据 ====================
    public byte[] readBlock(int height) {
        try {
            for(ContainerIndexEntry entry : indexList){
                if(entry.height == height){
                    byte[] data = new byte[entry.length];
                    raf.seek(entry.offset + 4); // 跳过长度 int
                    raf.readFully(data);
                    return data;
                }
            }
        } catch(IOException e){
            e.printStackTrace();
            System.err.println("读取区块失败: " + e.getMessage());
        }
        return null;
    }

    // ==================== 头部/索引/尾部操作 ====================

    private void writeIndexEntry(RandomAccessFile raf, ContainerIndexEntry entry) throws IOException {
        raf.writeInt(entry.height);
        raf.writeLong(entry.offset);
        raf.writeInt(entry.length);
        raf.write(entry.blockHash);
    }

    private void writeFooter(RandomAccessFile raf, long indexOffset, long indexLength, byte[] hash) throws IOException {
        raf.writeLong(indexOffset);
        raf.writeLong(indexLength);
        raf.write(hash);
    }

    private void writeHead(RandomAccessFile raf, ContainerHead head) throws IOException {
        raf.write(head.magic.getBytes(StandardCharsets.UTF_8));         // 4 bytes
        raf.writeShort(head.version);             // 2 bytes
        raf.write(head.containerHash);            // 32 bytes
        raf.writeLong(head.baseTime);             // 8 bytes
        raf.writeInt(head.blockCount);            // 4 bytes
        raf.writeLong(head.indexOffset);          // 8 bytes
        raf.writeLong(head.indexLength);          // 8 bytes
        raf.write(head.reserved);                 // 填充固定大小
    }
    public ContainerHead getHead(){
        return head;
    }

    private ContainerHead readHead(RandomAccessFile raf) throws IOException {
        ContainerHead h = new ContainerHead();
        raf.seek(0);
        byte[] magicBytes = new byte[4];
        raf.readFully(magicBytes);
        h.magic = new String(magicBytes);

        h.version = raf.readShort();

        byte[] hash = new byte[32];
        raf.readFully(hash);
        h.containerHash = hash;

        h.baseTime = raf.readLong();
        h.blockCount = raf.readInt();
        h.indexOffset = raf.readLong();
        h.indexLength = raf.readLong();

        byte[] reserved = new byte[ContainerHead.FIXED_SIZE - 4 - 2 - 32 - 8 - 4 - 8 - 8];
        raf.readFully(reserved);
        h.reserved = reserved;
        return h;
    }

    private List<ContainerIndexEntry> readIndex(RandomAccessFile raf, long offset, long length) throws IOException {
        List<ContainerIndexEntry> list = new ArrayList<>();
        raf.seek(offset);
        long end = offset + length;
        while(raf.getFilePointer() < end){
            ContainerIndexEntry e = new ContainerIndexEntry();
            e.height = raf.readInt();
            e.offset = raf.readLong();
            e.length = raf.readInt();
            byte[] hash = new byte[32];
            raf.readFully(hash);
            e.blockHash = hash;
            list.add(e);
        }
        return list;
    }

    //容器完成数据写入
    public byte[] computeContainerHash() {
        try (RandomAccessFile r = new RandomAccessFile(filePath, "r")) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[1024*1024];
            int bytesRead;
            r.seek(0);
            while((bytesRead=r.read(buffer))!=-1){
                digest.update(buffer,0,bytesRead);
            }
            return digest.digest();
        } catch (IOException | NoSuchAlgorithmException e){
            e.printStackTrace();
            System.err.println("计算容器hash失败: "+e.getMessage());
            return new byte[32];
        }
    }

    // ==================== JSON 可视化 ====================
    public String headToJson() {
        return String.format("""
                {
                  "magic": "%s",
                  "version": %d,
                  "containerHash": "%s",
                  "baseTime": %d,
                  "blockCount": %d,
                  "indexOffset": %d,
                  "indexLength": %d
                }
                """,
                head.magic, head.version, bytesToHex(head.containerHash),
                head.baseTime, head.blockCount, head.indexOffset, head.indexLength
        );
    }

    public String indexToJson() {
        StringBuilder sb = new StringBuilder("[");
        for(ContainerIndexEntry e : indexList){
            sb.append(String.format("""
                    {"height": %d, "offset": %d, "length": %d, "blockHash": "%s"},
                    """, e.height, e.offset, e.length, bytesToHex(e.blockHash)));
        }
        if(sb.length()>1) sb.setLength(sb.length()-1); // 去掉最后逗号
        sb.append("]");
        return sb.toString();
    }

    private String bytesToHex(byte[] bytes){
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes){
            sb.append(String.format("%02x",b));
        }
        return sb.toString();
    }

}
