package org.example.core.ChainData;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import org.bouncycastle.util.encoders.Hex;

/**
 * SystemCall: 0x03 类型，用于修改全局治理参数和 Mini-Program 规则。
 * 只能由 SuperServer 发起。
 */
public class SystemCall extends AbstractQubeData {

    // 系统调用的子类型定义
    public static final byte SUB_TYPE_FEE_UPDATE = 0x01;
    public static final byte SUB_TYPE_RULE_DEPLOYMENT = 0x02;
    // ... 其他系统子类型

    private final byte callType;
    private final long effectiveGlobalHeight; // 【关键】决定该系统调用在全球哪个高度生效 (EGH)
    private final byte[] callPayload;        // 具体的规则或参数数据

    // ====================== 构造函数 ======================
    /**
     * @param callType                系统调用的子类型 (0x01, 0x02...)
     * @param effectiveGlobalHeight   该调用生效的 Layer 2 全局容器高度
     * @param callPayload             具体参数数据
     * @param feeAmount               系统调用通常费用为 0
     * @param superServerPubKey       发起调用的超级服务器公钥
     * @param signature               超级服务器对 Payload Body 的签名
     */
    public SystemCall(
            byte callType,
            long effectiveGlobalHeight,
            byte[] callPayload,
            long feeAmount,
            byte[] superServerPubKey,
            byte[] signature) {

        // 调用父类构造函数，设置 TypeID = 0x03 (SystemCall)
        super(ChainDataType.SYSTEM_CALL.typeId, feeAmount, superServerPubKey, signature);

        if (callPayload == null || callPayload.length == 0) {
            throw new IllegalArgumentException("SystemCall requires a non-empty payload.");
        }
        if (effectiveGlobalHeight <= 0) {
            throw new IllegalArgumentException("Effective Global Height must be positive.");
        }

        this.callType = callType;
        this.effectiveGlobalHeight = effectiveGlobalHeight;
        this.callPayload = callPayload;
    }

    public static SystemCall parseFrom(byte[] fullDataBytes) throws IOException {
        // [TODO: 实现细节] 需要实现完整的 Header 和 Payload Body 的反序列化逻辑
        // 重点是：确保 toPubkey, amount, assetId, memo 的读取顺序和长度与 getPayloadBody() 严格一致。
        throw new UnsupportedOperationException("Transaction Deserialization TBD.");
    }

    // ====================== 核心序列化与解析 ======================

    /**
     * 【核心实现】定义 Payload Body 的写入顺序和结构。
     */
    @Override
    protected byte[] getPayloadBody() throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(baos)) {

            // 1. 写入 CallType
            dos.writeByte(callType);
            // 2. 写入 EffectiveGlobalHeight (EGH)
            dos.writeLong(effectiveGlobalHeight);
            // 3. 写入 CallPayload (写入长度 + 写入内容)
            dos.writeInt(callPayload.length);
            dos.write(callPayload);

            dos.flush();
            return baos.toByteArray();
        }
    }

    // ====================== 可视化方法 (标准 3) ======================

    @Override
    public String toAuditString() {
        return String.format("SystemCall [Type=0x%s, EGH=%d, ServerID=%s...]",
                Hex.toHexString(new byte[]{this.callType}),
                this.effectiveGlobalHeight,
                Hex.toHexString(this.senderPubKey).substring(0, 10));
    }

    @Override
    public String toJSON() {
        return String.format(
                """
                {
                  "typeId": "%s",
                  "callType": "%s",
                  "effectiveGlobalHeight": %d,
                  "superServerPubKey": "%s",
                  "payloadLength": %d,
                  "feeAmount": %d
                }
                """,
                Hex.toHexString(new byte[]{this.typeId}),
                Hex.toHexString(new byte[]{this.callType}),
                this.effectiveGlobalHeight,
                Hex.toHexString(this.senderPubKey),
                this.callPayload.length,
                this.feeAmount
        );
    }
}