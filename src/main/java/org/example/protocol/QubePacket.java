package org.example.protocol;

import org.example.core.TimestampUtil;
import org.example.crypto.CryptoUtil;
import org.example.crypto.QubeSigner;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * 通讯数据包
 * 客户端生成：携带 clientTime
 * 服务器生成：可补充 serverTime
 * 所有时间存储/传输使用高进制字符串（32进制）
 */
public class QubePacket {

    public byte[] publicKey;      // 发送者公钥
    public long clientTime;       // 客户端时间
    public long serverTime;       // 服务器时间（接收时填充）
    public long nonce;            // 防重放随机数（可选）
    public byte[] payload;        // 业务数据字节体
    public byte[] signature;      // 签名

    // ====================== 构造方法 ======================

    /** 客户端构建 */
    public QubePacket(byte[] publicKey, long clientTime, long nonce, byte[] payload) {
        this.publicKey = publicKey;
        this.clientTime = clientTime;
        this.nonce = nonce;
        this.payload = payload;
    }

    /**
     * 使用私钥对数据包签名
     */
    public void sign(String privateKey) {
        byte[] dataToSign = buildSignData();
        this.signature = QubeSigner.signRaw(dataToSign, privateKey);
    }

    /**
     * 生成待签名数据：publicKey + clientTime + nonce + payload
     */
    private byte[] buildSignData() {
        ByteBuffer buffer = ByteBuffer.allocate(
                publicKey.length + 8 + 8 + payload.length
        );
        buffer.put(publicKey);
        buffer.putLong(clientTime);
        buffer.putLong(nonce);
        buffer.put(payload);
        return buffer.array();
    }

    // ====================== 序列化 ======================

    /**
     * 将数据包转为字节数组，所有时间字段使用高进制字符串存储
     */
    public byte[] toBytes() {
        if(signature == null){
            System.out.println("请完成签名后生成数据");
            return null;
        }

        // clientTime / serverTime 转 32进制字符串
        String clientTimeStr = TimestampUtil.encode(clientTime);
        String serverTimeStr = TimestampUtil.encode(serverTime);

        byte[] clientTimeBytes = clientTimeStr.getBytes(StandardCharsets.UTF_8);
        byte[] serverTimeBytes = serverTimeStr.getBytes(StandardCharsets.UTF_8);

        ByteBuffer buffer = ByteBuffer.allocate(
                4 + publicKey.length +
                        4 + clientTimeBytes.length +
                        4 + serverTimeBytes.length +
                        8 + // nonce仍使用8字节long
                        4 + payload.length +
                        4 + signature.length
        );

        buffer.putInt(publicKey.length);
        buffer.put(publicKey);

        buffer.putInt(clientTimeBytes.length);
        buffer.put(clientTimeBytes);

        buffer.putInt(serverTimeBytes.length);
        buffer.put(serverTimeBytes);

        buffer.putLong(nonce);

        buffer.putInt(payload.length);
        buffer.put(payload);

        buffer.putInt(signature.length);
        buffer.put(signature);

        return buffer.array();
    }

    // ====================== 解析 ======================

    public static QubePacket parse(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);

        int pkLen = buffer.getInt();
        byte[] publicKey = new byte[pkLen];
        buffer.get(publicKey);

        int clientTimeLen = buffer.getInt();
        byte[] clientTimeBytes = new byte[clientTimeLen];
        buffer.get(clientTimeBytes);
        long clientTime = TimestampUtil.decode(new String(clientTimeBytes, StandardCharsets.UTF_8));

        int serverTimeLen = buffer.getInt();
        byte[] serverTimeBytes = new byte[serverTimeLen];
        buffer.get(serverTimeBytes);
        long serverTime = TimestampUtil.decode(new String(serverTimeBytes, StandardCharsets.UTF_8));

        long nonce = buffer.getLong();

        int payloadLen = buffer.getInt();
        byte[] payload = new byte[payloadLen];
        buffer.get(payload);

        int sigLen = buffer.getInt();
        byte[] signature = new byte[sigLen];
        buffer.get(signature);

        QubePacket packet = new QubePacket(publicKey, clientTime, nonce, payload);
        packet.serverTime = serverTime;
        packet.signature = signature;

        return packet;
    }

    // ====================== 验证 ======================

    public boolean verify() {
        return QubeSigner.verifyRaw(buildSignData(), signature, publicKey);
    }
}
