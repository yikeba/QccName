package org.example.protocol;

// QubeDataReceiver.java —— 全球最硬量子数据接收器（永封版）

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import org.bouncycastle.util.encoders.Hex;
import org.example.core.ChainData.*;
import org.example.crypto.QubeSigner;
import org.example.crypto.QubeAddressUtil;
import org.example.storage.AddressIndexService;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.zip.GZIPInputStream;

public final class QubeDataReceiver {

    private static final byte[] MAGIC = "QBDA".getBytes(); // QubeData
    private static final byte VERSION = 0x01;

    private byte[] rawBytes;        // 解码后的原始二进制
    private String address;
    private byte[] signature;
    private byte[] compressedData;
    private String jsonData;        // 解压后的原始JSON
    private AbstractQubeData parsedData; // 最终业务对象

    // ==================== 构造：支持 byte[] 和 InputStream ====================
    public QubeDataReceiver(byte[] base64Data) {
        this(new ByteArrayInputStream(base64Decode(base64Data)));
    }

    public QubeDataReceiver(InputStream inputStream) {
        try {
            byte[] all = inputStream.readAllBytes();
            if (all.length < 20) throw new IllegalArgumentException("数据太短");
            this.rawBytes = base64Decode(all); // 如果前端传base64，就解
            parseProtocol();
            verifyAndDecompress();
            parseBusinessData();
        } catch (Exception e) {
            throw new RuntimeException("量子数据解析失败", e);
        }
    }

    // ==================== 核心解析协议 ====================
    private void parseProtocol() {
        ByteBuffer buf = ByteBuffer.wrap(rawBytes);

        // 1. Magic + Version
        byte[] magic = new byte[4];
        buf.get(magic);
        if (!java.util.Arrays.equals(magic, MAGIC)) {
            throw new SecurityException("非法数据：Magic错误");
        }
        if (buf.get() != VERSION) {
            throw new SecurityException("不支持的协议版本");
        }

        // 2. 地址
        int addrLen = buf.getShort() & 0xFFFF;
        byte[] addrBytes = new byte[addrLen];
        buf.get(addrBytes);
        this.address = new String(addrBytes, StandardCharsets.UTF_8);
        if (!QubeAddressUtil.isValidAddress(address)) {
            throw new SecurityException("无效地址: " + address);
        }

        // 3. 签名
        int signLen = buf.getInt();
        this.signature = new byte[signLen];
        buf.get(this.signature);

        // 4. 剩余为压缩数据
        this.compressedData = new byte[buf.remaining()];
        buf.get(this.compressedData);

        System.out.println("协议解析成功 → 地址: " + address + " 签名长度: " + signLen + " 压缩数据: " + compressedData.length + " bytes");
    }

    // ==================== 验签 + 解压（最硬一步！） ====================
    private void verifyAndDecompress() throws Exception {
        // 1. 先恢复公钥（三级缓存）
        String pubKeyHex = AddressIndexService.getInstance().getPubKeyHex(this.address);

        // 2. 对压缩数据进行Dilithium5验签
        if (!QubeSigner.verifyRaw(compressedData, signature, pubKeyHex)) {
            throw new SecurityException("【量子签名验证失败】数据被篡改！地址: " + address);
        }

        // 3. 验签通过 → 解压
        try (GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(compressedData))) {
            this.jsonData = new String(gis.readAllBytes(), StandardCharsets.UTF_8);
        }

        System.out.println("验签成功 + 解压成功 → JSON长度: " + jsonData.length());
    }

    // ==================== 解析业务数据 ====================
    // QubeDataReceiver.java —— 终极修正版（100% 使用你的 QubeDataFactory）
    private void parseBusinessData() throws Exception {
        // 1. 解压后的 jsonData 是原始业务JSON
        // 2. 我们现在把它转成严格的 byte[] 格式，走你最硬的 QubeDataFactory 解析！

        // 模拟客户端序列化流程：业务对象 → toByteArray()
        // 注意：这里我们需要一个临时的“伪对象”来生成标准字节流
        // 实际主网中，客户端必须按标准序列化，我们这里做兼容转换

        // 方案一：强制要求客户端传标准字节流（最硬！推荐！）
        // 方案二：临时兼容JSON（只用于过渡）

        // 我们现在采用【过渡兼容方案】：JSON → 临时转成标准字节流 → 走工厂
        JSONObject json = JSON.parseObject(jsonData);
        String type = json.getString("type");

        // 创建一个临时的 AbstractQubeData 子类实例，只为生成标准字节流
        AbstractQubeData tempData = switch (type) {
            case "transfer" -> createTempTransaction(json);
            case "data_record" -> createTempDataRecord(json);
            case "system_call" -> createTempSystemCall(json);
            default -> throw new IllegalArgumentException("未知类型: " + type);
        };

        // 生成标准字节流
        byte[] standardBytes = tempData.toByteArray();

        // 关键！走你最硬的 QubeDataFactory 解析！
        this.parsedData = (AbstractQubeData) QubeDataFactory.parse(standardBytes);

        System.out.println("业务数据解析成功 → 通过QubeDataFactory工厂 → " + parsedData.toAuditString());
    }

    private AbstractQubeData createTempTransaction(JSONObject json) {
        return new Transaction(
                json.getString("to").getBytes(),
                json.getLongValue("amount"),
                json.getIntValue("assetId"),
                json.getString("memo"),
                100L,
                Hex.decode("00".repeat(976)), // 临时公钥，实际不参与签名
                new byte[2420] // 临时签名
        );
    }

    // ==================== 对外API ====================
    public AbstractQubeData getParsedData() { return parsedData; }
    public String getSenderAddress() { return address; }
    public String getRawJson() { return jsonData; }

    // 工具
    private static byte[] base64Decode(byte[] input) {
        return java.util.Base64.getDecoder().decode(input);
    }
}