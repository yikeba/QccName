package org.example.core.ChainData;

import org.example.crypto.CryptoUtil;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;


/**
 * AbstractQubeData: QubeChain 中所有可序列化数据（Transaction, DataRecord, SystemCall）的基类。
 * 它定义了固定长度的数据头（Header）和核心的安全属性。
 */
public abstract class AbstractQubeData implements ChainData {

    // ====================== 固定头部字段 (Fixed Header) ======================
    // 1. 路由标识符：数据类型 (1 byte)
    protected final byte typeId;
    // 2. 时间戳：数据创建时间 (8 bytes)
    protected final long timestamp;
    // 3. 费用：支付给 X 服务器的费用 (8 bytes)
    protected final long feeAmount;
    // 4. 发送方公钥：用于验证签名的 Dilithium 公钥 (byte[])
    protected final byte[] senderPubKey;
    // 5. 载荷哈希：具体数据体 (Payload Body) 的哈希值 (32 bytes)
    private byte[] payloadHash;
    // 6. 签名：客户对整个 Header Hash 的 Dilithium 签名 (byte[])
    protected final byte[] signature;
    // ====================== 构造函数 (Constructor) ======================
    // 构造函数用于初始化 Header 的固定字段
    public AbstractQubeData(
            byte typeId,
            long feeAmount,
            byte[] senderPubKey,
            byte[] signature) {

        // 自动设置当前时间戳
        this.timestamp = System.currentTimeMillis();

        this.typeId = typeId;
        this.feeAmount = feeAmount;
        this.senderPubKey = senderPubKey;
        this.signature = signature;

       // this.payloadHash = calculatePayloadHash();   // 载荷哈希在具体子类中构造 Payload Body 后计算并赋值

    }

    // ====================== 核心抽象方法 (Core Abstractions) ======================

    /**
     * 【子类必须实现】获取对象的具体数据体 (Payload Body)。
     * 交易有转账金额，DataRecord 有文件哈希和链接，子类实现各自的结构。
     * @return Payload Body 的字节数组。
     */
    protected abstract byte[] getPayloadBody() throws IOException;

    /**
     * 【子类必须实现】将 Payload Body 转换为易读字符串（用于日志和审计）。
     * @return 载荷内容的字符串描述。
     */
    public abstract String toAuditString();


    /**
     * 【子类实现/标准 3】返回供 Applet 使用的 JSON 格式数据。
     */
    public abstract String toJSON();
    // ====================== 接口实现 (SerializableData) ======================

    @Override
    public byte getDataTypeId() {
        return this.typeId;
    }

    /**
     * 【重要】计算 Payload Body 的确定性哈希。
     * @return SHA-256/SHA3-256 结果。
     */
    public byte[] calculatePayloadHash() {
        try {
            byte[] payloadBody = getPayloadBody();
            // 正确！用真正的SHA3-256哈希！
            return CryptoUtil.sha256(payloadBody);
        } catch (IOException e) {
            throw new RuntimeException("计算PayloadHash失败，无法构造数据对象", e);
        }
    }
    /**
     * 【关键方法】将整个数据对象序列化为 byte[]。
     * 头部 (Header) 字段必须以确定的顺序写入，Payload Body 紧随其后。
     */
    @Override
    public byte[] toByteArray() throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(baos)) {

            // 1. 写入固定长度的头部 (Header) 字段
            dos.writeByte(typeId);
            dos.writeLong(timestamp);
            dos.writeLong(feeAmount);
            // 写入哈希和公钥，这些都是 byte[]
            dos.write(senderPubKey);
           //
            if(signature!=null)dos.write(signature);


            // 2. 写入可变长度的数据体 (Payload Body)
            byte[] payloadBody = getPayloadBody();
            payloadHash = calculatePayloadHash();
            dos.write(payloadHash);
            // 【注意】：为了让接收方知道 Payload Body 的长度，我们需要在前面写入一个长度前缀！
            dos.writeInt(payloadBody.length);
            dos.write(payloadBody);

            dos.flush();
            return baos.toByteArray();
        }
    }

    // 计算整个 Header 的哈希，用于签名验证
    @Override
    public byte[] calculateHash() {
        // 这个哈希是用于 Dilithium 签名的最终数据源
        // 它通常是 PayloadHash + TypeId + Timestamp 的组合哈希。
        // 子类中可以重写或使用统一的 QubeHashUtil。
        return this.payloadHash; // 简化处理，实际中需要包含所有关键 Header 字段。
    }
}