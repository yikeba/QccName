package qcc.name.core;

import qcc.name.codec.QccCanonicalReader;
import qcc.name.codec.QccCanonicalWriter;
import qcc.name.codec.Sha3;

import java.util.List;

/**
 * 一条操作的完整输入。这就是写进 OpLogStore 的那条记录。
 *
 * ═══ 签名为什么不在这里 ═══════════════════════════════════════════
 * ML-DSA-87 单个签名 4,627 字节,bindAddr 双签就是 9KB。十万条操作的日志
 * 会超过 460MB,重放和同步都变重。所以照搬 QCC 自身的做法:日志只存
 * sigHash(32 字节),签名本体放 SignatureVault,按 sigHash 索引。
 *   - 只想验证状态推进的验证者:拉日志就够,25MB
 *   - 要连签名一起验的:再拉一份签名库
 * 这与 QccBaseData.signatureHash 是同一个模式。
 *
 * ═══ admitHeight 为什么必须进日志 ═════════════════════════════════
 * 防重放检查是 "blockHeight 与当时的链高度相差是否在窗口内"。如果"当时的
 * 链高度"不记录下来,重放者根本不知道那个值,这一项检查在重放时会给出
 * 不同的 resultCode —— execHash 直接分叉。所以由 leader 把准入高度写进
 * 日志,检查变成纯粹关于记录本身的函数,任何时候重放结果都一样。
 *
 * leader 可以在 admitHeight 上撒谎,但只能在一个有界范围内,而且 epoch
 * header 的 endBlockHeight 会交叉约束它(本 epoch 内所有 admitHeight
 * 必须 <= endBlockHeight),伪造会被独立发现。
 *
 * sigValid 由核心之外的批量验签器填入。验签结果是确定的(同样的消息+签名
 * +公钥永远同一个答案),所以可以并行做而不破坏确定性 —— 这正是"把确定性
 * 边界画小"换来的吞吐。验证者重放时会自己再验一遍。
 */
public final class OpInput {

    public final int          opCode;
    public final long         blockHeight;   // 客户端签名时锁定的高度,由用户签名覆盖
    public final long         admitHeight;   // leader 接纳这条操作时的链高度,进日志
    public final byte[]       payload;       // 规范二进制,格式由各 handler 定义
    public final List<String> signers;       // 声称的签名者地址,顺序与 OpSpec.signers 对应
    public final byte[]       sigHash;       // SHA3-256(canonical(签名列表)),进 execHash

    // 以下不进日志、不参与 execHash 的输入,由外层填充后传入状态机
    public final boolean      sigValid;      // 批量验签结果(重放时验证者自己重算)
    public final long         seq;           // OpLogStore 分配
    public final PledgeFact   pledge;        // 仅 register 用;其余传 none()

    public OpInput(int opCode, long blockHeight, long admitHeight, byte[] payload,
                   List<String> signers, byte[] sigHash, boolean sigValid, long seq,
                   PledgeFact pledge) {
        if (payload == null) throw new IllegalArgumentException("payload is null");
        if (signers == null || signers.isEmpty()) throw new IllegalArgumentException("signers 不能为空");
        if (sigHash == null || sigHash.length != Sha3.HASH_LEN)
            throw new IllegalArgumentException("sigHash 必须是 32 字节");
        if (blockHeight < 0) throw new IllegalArgumentException("blockHeight 不能为负");
        if (admitHeight < 0) throw new IllegalArgumentException("admitHeight 不能为负");
        this.opCode = opCode; this.blockHeight = blockHeight; this.admitHeight = admitHeight;
        this.payload = payload.clone(); this.signers = List.copyOf(signers);
        this.sigHash = sigHash.clone(); this.sigValid = sigValid;
        this.seq = seq;
        this.pledge = pledge == null ? PledgeFact.none() : pledge;
    }

    /** 写进日志的规范字节。不含 sigValid/seq/pledge —— 那些是派生的,不是输入。 */
    public byte[] encodeForLog() {
        return new QccCanonicalWriter()
                .u8(opCode).u64(blockHeight).u64(admitHeight).bytes(payload)
                .strList(signers).hash32(sigHash)
                .toBytes();
    }

    /** 从日志字节还原。重放路径唯一的入口。 */
    public static OpInput decodeFromLog(byte[] b, boolean sigValid, long seq, PledgeFact pledge) {
        QccCanonicalReader r = new QccCanonicalReader(b);
        int opCode      = r.u8();
        long height     = r.u64();
        long admit      = r.u64();
        byte[] payload  = r.bytes();
        List<String> sg = r.strList();
        byte[] sigHash  = r.hash32();
        r.finish();
        return new OpInput(opCode, height, admit, payload, sg, sigHash, sigValid, seq, pledge);
    }
}
