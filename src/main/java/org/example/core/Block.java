package org.example.core;

import org.example.core.ChainData.AbstractQubeData;
import org.example.core.ChainData.ChainData;
import org.bouncycastle.util.encoders.Hex;
import org.example.core.ChainData.QubeDataFactory;
import org.example.crypto.CryptoUtil;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * QubeChain ∞ 终极区块对象
 * 完美适配你的 AbstractQubeData + 固定头 + 变长体 + Dilithium签名
 */
public class Block {

    // ==================== 区块头（固定部分） ====================
    public short height;                    // 容器内高度（short够用65k）
    public byte[] prevBlockHash;            // 上一个区块哈希（32字节）
    public byte[] merkleRoot;               // Merkle根（32字节）
    public long timestamp;                  // 区块时间
    public short dataCount;                 // 数据条数（short够用）

    // ==================== 区块体（变长） ====================
    public final List<AbstractQubeData> dataList = new ArrayList<>();

    // ==================== 区块哈希（密封后计算） ====================
    public byte[] blockHash;

    public Block(short height, byte[] prevBlockHash) {
        this.height = height;
        this.prevBlockHash = prevBlockHash != null ? prevBlockHash : new byte[32];
        this.timestamp = System.currentTimeMillis();
    }

    // 添加任意数据（你4种子类都行！！！）
    public void addData(AbstractQubeData data) {
        dataList.add(data);
        dataCount = (short) dataList.size();
    }

    // 密封区块（计算所有哈希）
    public void seal() {
        this.merkleRoot = calculateMerkleRoot();
        this.blockHash = calculateBlockHash();
    }

    // 计算Merkle根（基于每条数据的calculateHash()）
    private byte[] calculateMerkleRoot() {
        if (dataList.isEmpty()) return new byte[32];
        List<byte[]> hashes = new ArrayList<>();
        for (AbstractQubeData data : dataList) {
            hashes.add(data.calculateHash());
        }
        return buildMerkleRoot(hashes);
    }

    // 计算区块哈希（只包含头 + merkleRoot）
    private byte[] calculateBlockHash() {
        ByteBuffer buffer = ByteBuffer.allocate(256);
        buffer.putShort(height);
        buffer.put(prevBlockHash);
        buffer.put(merkleRoot);
        buffer.putLong(timestamp);
        buffer.putShort(dataCount);
        buffer.flip();
        return CryptoUtil.sha256(buffer.array(), 0, buffer.limit());
    }

    // ==================== 序列化（完美适配你的toByteArray()） ====================
    public byte[] serialize() throws IOException {
        seal(); // 确保已密封

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(baos)) {

            // 1. 写区块头（固定长度）
            dos.writeByte(0x01);                    // 版本
            dos.writeShort(height);
            dos.write(prevBlockHash);
            dos.write(merkleRoot);
            dos.writeLong(timestamp);
            dos.writeShort(dataCount);
            dos.write(blockHash);

            // 2. 写每条数据（直接调用你神级的toByteArray()！！！）
            for (AbstractQubeData data : dataList) {
                byte[] dataBytes = data.toByteArray();
                dos.writeInt(dataBytes.length);     // 长度前缀
                dos.write(dataBytes);               // 数据体
            }

            dos.flush();
            return baos.toByteArray();
        }
    }

    // ==================== 反序列化（完美还原你的数据对象） ====================
    public static Block deserialize(byte[] blockBytes) throws IOException {
        try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(blockBytes))) {

            Block block = new Block((short) 0, null);

            // 读头
            dis.readByte(); // 版本
            block.height = dis.readShort();
            dis.readFully(block.prevBlockHash = new byte[32]);
            dis.readFully(block.merkleRoot = new byte[32]);
            block.timestamp = dis.readLong();
            block.dataCount = dis.readShort();
            dis.readFully(block.blockHash = new byte[32]);

            // 读每条数据
            for (int i = 0; i < block.dataCount; i++) {
                int len = dis.readInt();
                byte[] dataBytes = new byte[len];
                dis.readFully(dataBytes);

                // 用你的神级工厂还原！！！
                ChainData data = QubeDataFactory.parse(dataBytes);
                block.dataList.add((AbstractQubeData) data);
            }

            return block;
        }
    }

    // ==================== 可视化 ====================
    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"height\": ").append(height).append(",\n");
        sb.append("  \"blockHash\": \"").append(Hex.toHexString(blockHash)).append("\",\n");
        sb.append("  \"prevBlockHash\": \"").append(Hex.toHexString(prevBlockHash)).append("\",\n");
        sb.append("  \"timestamp\": ").append(timestamp).append(",\n");
        sb.append("  \"dataCount\": ").append(dataCount).append(",\n");
        sb.append("  \"data\": [\n");

        for (int i = 0; i < dataList.size(); i++) {
            sb.append("    ").append(dataList.get(i).toJSON());
            if (i < dataList.size() - 1) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ]\n}");
        return sb.toString();
    }

    // Merkle树
    private byte[] buildMerkleRoot(List<byte[]> hashes) {
        if (hashes.size() == 1) return hashes.get(0);
        List<byte[]> parents = new ArrayList<>();
        for (int i = 0; i < hashes.size(); i += 2) {
            byte[] left = hashes.get(i);
            byte[] right = i + 1 < hashes.size() ? hashes.get(i + 1) : left;
            parents.add(CryptoUtil.sha256(left, right));
        }
        return buildMerkleRoot(parents);
    }
}