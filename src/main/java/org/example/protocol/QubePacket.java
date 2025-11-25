package org.example.protocol;

import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.example.crypto.QubeAddressUtil;
import org.example.crypto.QubeSigner; // 假设这是您前面提到的包含 signRaw 和 verifyRaw 的类

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * 终极健壮版 QubePacket (Dilithium5)
 * 特点：
 * 1. 协议健壮：通过新增 payloadLength (4 字节) 字段，精确处理变长 Payload。
 * 2. 数据一致：签名数据与序列化数据完全一致 (包含 serverTime 即使为 0)。
 * 3. 使用固定常量，便于维护 Dilithium 版本。
 */
public class QubePacket {

    // --- Dilithium5 固定长度常量 ---
    // 请根据您实际使用的 Bouncy Castle 版本和 Dilithium5 模式进行核实
    private static final int PUBLIC_KEY_LEN = 2592; // Dilithium5 公钥长度
    private static final int SIGNATURE_LEN = 4627; // 使用您本地测试的 Dilithium5 签名长度 (4627)

    // --- 协议定长字段长度 ---
    private static final int TIME_AND_NONCE_LEN = 8 + 8 + 8; // clientTime + serverTime + nonce
    private static final int PAYLOAD_LEN_FIELD = 4; // payloadLength 字段的长度 (int)

    // --- 字段 ---
    public final byte[] publicKey;      // 2592
    public final long clientTime;       // 8
    public long serverTime;             // 8 (服务器填充)
    public final long nonce;            // 8
    public final byte[] payload;        // 变长
    public byte[] signature;            // 4627

    // 客户端构造（serverTime 默认为 0）
    public QubePacket(byte[] publicKey, long clientTime, long nonce, byte[] payload) {
        if (publicKey.length != PUBLIC_KEY_LEN) {
            throw new IllegalArgumentException("公钥长度必须是 " + PUBLIC_KEY_LEN + " 字节 (Dilithium5)");
        }
        this.publicKey = publicKey;
        this.clientTime = clientTime;
        this.nonce = nonce;
        this.payload = payload;
        this.serverTime = 0L;
        this.signature = null;
    }

    /** 签名（使用私钥对象） */
    public void sign(DilithiumPrivateKeyParameters privKey) {
        this.signature = QubeSigner.signRaw(buildSignData(), privKey);
        // 确保签名长度符合预期
        if (this.signature.length != SIGNATURE_LEN) {
            // 这是一个重要警告，如果长度不一致，可能会导致解析失败
            System.err.println("警告：实际签名长度 " + this.signature.length + " 与预期长度 " + SIGNATURE_LEN + " 不符！");
        }
        boolean isok=verify();
        System.out.println("签名本地验证结果:" + isok + " 本地签名长度:" + signature.length);
    }

    /** 验证签名（本地和网络接收后都用这个） */
    public boolean verify() {
        if (signature == null) return false;
        // 验证时使用 buildSignData() 生成的原始数据
        return QubeSigner.verifyRaw(buildSignData(), signature, publicKey);
    }

    /** 关键：签名数据 和 序列化数据 必须完全一样！
     * 数据体：publicKey | clientTime | serverTime | nonce | payloadLength | payload
     */
    private byte[] buildSignData() {
        return ByteBuffer.allocate(PUBLIC_KEY_LEN + TIME_AND_NONCE_LEN + PAYLOAD_LEN_FIELD + payload.length)
                .put(publicKey)
                .putLong(clientTime)
                .putLong(serverTime)   // 必须包含！即使是0
                .putLong(nonce)
                .putInt(payload.length) // 新增：Payload 长度字段
                .put(payload)
                .array();
    }

    /** 序列化成字节（上链/传网络）
     * 数据体：publicKey | clientTime | serverTime | nonce | payloadLength | payload | signature
     */
    public byte[] toBytes() {
        if (signature == null) {
            throw new IllegalStateException("请先签名后再序列化");
        }
        // 总长度 = 公钥 + 时间/Nonce + Payload长度字段 + Payload + 签名
        return ByteBuffer.allocate(PUBLIC_KEY_LEN + TIME_AND_NONCE_LEN + PAYLOAD_LEN_FIELD + payload.length + SIGNATURE_LEN)
                .put(publicKey)
                .putLong(clientTime)
                .putLong(serverTime)
                .putLong(nonce)
                .putInt(payload.length) // 新增：Payload 长度字段
                .put(payload)
                .put(signature)
                .array();
    }

    /** 从字节解析（网络接收或链上读取） */
    public static QubePacket parse(byte[] data) {
        ByteBuffer buf = ByteBuffer.wrap(data);

        // 1. 读取公钥 (固定长度)
        byte[] publicKey = new byte[PUBLIC_KEY_LEN];
        buf.get(publicKey);

        // 2. 读取时间/Nonce (固定长度)
        long clientTime = buf.getLong();
        long serverTime = buf.getLong();
        long nonce = buf.getLong();

        // 3. 读取 Payload 长度字段 (固定长度)
        int payloadLen = buf.getInt();

        // 4. 读取 Payload (变长)
        byte[] payload = new byte[payloadLen];
        buf.get(payload);

        // 5. 读取 Signature (固定长度)
        byte[] signature = new byte[SIGNATURE_LEN];
        // 在读取前进行检查，防止越界
        if (buf.remaining() != SIGNATURE_LEN) {
            throw new IllegalArgumentException("数据包解析错误: 剩余字节数 " + buf.remaining() + " 不等于预期签名长度 " + SIGNATURE_LEN);
        }
        buf.get(signature);

        QubePacket packet = new QubePacket(publicKey, clientTime, nonce, payload);
        packet.serverTime = serverTime;
        packet.signature = signature;
        return packet;
    }

    // 可选：人性化打印
    @Override
    public String toString() {
        String address = QubeAddressUtil.pubKeyToAddress(publicKey);
        String payloadStr;
        try {
            payloadStr = new String(payload, StandardCharsets.UTF_8);
        } catch (Exception e) {
            payloadStr = "[非UTF-8数据]";
        }

        return "QubePacket{" +
                "address=" + address +
                ", clientTime=" + clientTime +
                ", serverTime=" + serverTime +
                ", nonce=" + nonce +
                ", payload=" + payloadStr +
                ", verified=" + verify() +
                '}';
    }
}