package org.example.core.ChainData;

import org.bouncycastle.util.encoders.Hex;
import org.example.core.TimestampUtil;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 通用交易数据类（客户端生成 + 服务器确认）
 * 核心字段：
 * from/to/amount/fee/memo/contractAddress/hash
 * clientTime/ serverTime 高进制编码存储
 */
public class TransactionData {

    private final String fromAddress;
    private final String toAddress;
    private final long amount;
    private final long fee;
    private final String memo;
    private final String contractAddress;  // 发送方可为空，接收方补充
    private final String hash;             // 数据完整性验证

    private long clientTime;   // 客户端生成时间
    private long serverTime;   // 服务器记录时间

    private static final int MEMO_MAX_LENGTH = 30;

    // ====================== 构造函数 ======================

    /** 客户端构造交易数据 */
    public TransactionData(String from, String to, long amount, long fee,
                           String memo, String contractAddress, long clientTime) {
        if(from == null || to == null || from.isEmpty() || to.isEmpty()){
            throw new IllegalArgumentException("from/to address不能为空");
        }
        if(amount <= 0 || fee < 0){
            throw new IllegalArgumentException("金额或手续费不合法");
        }
        if(memo != null && memo.length() > MEMO_MAX_LENGTH){
            throw new IllegalArgumentException("memo长度不能超过" + MEMO_MAX_LENGTH + "字符");
        }

        this.fromAddress = from;
        this.toAddress = to;
        this.amount = amount;
        this.fee = fee;
        this.memo = (memo != null) ? memo : "";
        this.contractAddress = contractAddress; // 发送方可为空
        this.clientTime = clientTime;
        this.serverTime = 0L; // 服务器记录，接收时填充
        this.hash = computeHash(contractAddress);
    }

    /** 接收方构造交易数据（payload + contractAddress + clientTime + serverTime） */
    public TransactionData(byte[] payload, String contractAddress) throws IOException {
        try(ByteArrayInputStream bais = new ByteArrayInputStream(payload);
            DataInputStream dis = new DataInputStream(bais)) {

            int fromLen = dis.readInt();
            byte[] fromBytes = new byte[fromLen];
            dis.readFully(fromBytes);
            this.fromAddress = new String(fromBytes, StandardCharsets.UTF_8);

            int toLen = dis.readInt();
            byte[] toBytes = new byte[toLen];
            dis.readFully(toBytes);
            this.toAddress = new String(toBytes, StandardCharsets.UTF_8);

            this.amount = dis.readLong();
            this.fee = dis.readLong();

            int memoLen = dis.readInt();
            byte[] memoBytes = new byte[memoLen];
            dis.readFully(memoBytes);
            this.memo = new String(memoBytes, StandardCharsets.UTF_8);

            if(this.memo.length() > MEMO_MAX_LENGTH){
                throw new IllegalArgumentException("memo长度不能超过" + MEMO_MAX_LENGTH + "字符");
            }

            // clientTime / serverTime
            int clientTimeLen = dis.readInt();
            byte[] clientTimeBytes = new byte[clientTimeLen];
            dis.readFully(clientTimeBytes);
            this.clientTime = TimestampUtil.decode(new String(clientTimeBytes, StandardCharsets.UTF_8));

            int serverTimeLen = dis.readInt();
            byte[] serverTimeBytes = new byte[serverTimeLen];
            dis.readFully(serverTimeBytes);
            this.serverTime = TimestampUtil.decode(new String(serverTimeBytes, StandardCharsets.UTF_8));

            this.contractAddress = contractAddress;
            validateFields();

            // 解析 hash
            int hashLen = dis.readInt();
            if(hashLen > 0){
                byte[] hashBytes = new byte[hashLen];
                dis.readFully(hashBytes);
                this.hash = new String(hashBytes, StandardCharsets.UTF_8);
            } else {
                this.hash = computeHash(contractAddress);
            }

            if(!verifyHash(contractAddress)){
                throw new IllegalArgumentException("交易数据 hash 验证失败，数据可能被篡改");
            }
        }
    }

    // ====================== 核心方法 ======================

    private void validateFields() {
        if(fromAddress == null || fromAddress.isEmpty())
            throw new IllegalArgumentException("fromAddress非法");
        if(toAddress == null || toAddress.isEmpty())
            throw new IllegalArgumentException("toAddress非法");
        if(amount <= 0)
            throw new IllegalArgumentException("amount必须大于0");
        if(fee < 0)
            throw new IllegalArgumentException("fee不能小于0");
    }

    /** 发送方生成 payload 数据 */
    public byte[] toBytes() throws IOException {
        byte[] clientTimeBytes = TimestampUtil.encode(clientTime).getBytes(StandardCharsets.UTF_8);
        byte[] serverTimeBytes = TimestampUtil.encode(serverTime).getBytes(StandardCharsets.UTF_8);

        try(ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos)) {

            byte[] fromBytes = fromAddress.getBytes(StandardCharsets.UTF_8);
            dos.writeInt(fromBytes.length); dos.write(fromBytes);

            byte[] toBytes = toAddress.getBytes(StandardCharsets.UTF_8);
            dos.writeInt(toBytes.length); dos.write(toBytes);

            dos.writeLong(amount);
            dos.writeLong(fee);

            byte[] memoBytes = memo.getBytes(StandardCharsets.UTF_8);
            dos.writeInt(memoBytes.length); dos.write(memoBytes);

            dos.writeInt(clientTimeBytes.length); dos.write(clientTimeBytes);
            dos.writeInt(serverTimeBytes.length); dos.write(serverTimeBytes);

            byte[] hashBytes = hash.getBytes(StandardCharsets.UTF_8);
            dos.writeInt(hashBytes.length); dos.write(hashBytes);

            dos.flush();
            return baos.toByteArray();
        }
    }

    /** 计算交易数据 hash */
    public String computeHash(String contractAddr) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(fromAddress.getBytes(StandardCharsets.UTF_8));
            digest.update(toAddress.getBytes(StandardCharsets.UTF_8));
            digest.update(longToBytes(amount));
            digest.update(longToBytes(fee));
            digest.update(memo.getBytes(StandardCharsets.UTF_8));
            digest.update(longToBytes(clientTime));
            digest.update(longToBytes(serverTime));
            if(contractAddr != null){
                digest.update(contractAddr.getBytes(StandardCharsets.UTF_8));
            }
            return Hex.toHexString(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("无法计算交易hash", e);
        }
    }

    public boolean verifyHash(String contractAddr) {
        return computeHash(contractAddr).equals(this.hash);
    }

    private byte[] longToBytes(long value){
        return new byte[]{
                (byte)(value >> 56),(byte)(value >> 48),(byte)(value >> 40),(byte)(value >> 32),
                (byte)(value >> 24),(byte)(value >> 16),(byte)(value >> 8),(byte)value
        };
    }

    // ====================== JSON 可视化 ======================
    public String toJSON() {
        return String.format(
                """
                {
                  "from": "%s",
                  "to": "%s",
                  "amount": %d,
                  "fee": %d,
                  "contractAddress": "%s",
                  "memo": "%s",
                  "clientTime": "%s",
                  "serverTime": "%s",
                  "hash": "%s"
                }
                """,
                fromAddress, toAddress, amount, fee, contractAddress, memo,
                TimestampUtil.encode(clientTime),
                TimestampUtil.encode(serverTime),
                hash
        );
    }

    // ====================== Getter ======================
    public String getFromAddress() { return fromAddress; }
    public String getToAddress() { return toAddress; }
    public long getAmount() { return amount; }
    public long getFee() { return fee; }
    public String getMemo() { return memo; }
    public String getContractAddress() { return contractAddress; }
    public String getHash() { return hash; }
    public long getClientTime() { return clientTime; }
    public long getServerTime() { return serverTime; }
    public void setServerTime(long serverTime) { this.serverTime = serverTime; }
}
