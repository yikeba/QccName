package qcc.name.frame;

import qcc.name.codec.QccCanonicalReader;
import qcc.name.codec.QccCanonicalWriter;
import qcc.name.codec.Sha3;
import qcc.name.core.FrameInput;
import qcc.name.op.NameOp;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * 同步凭证：一条操作的全部事实 + 执行哈希。节点之间直接推送它，不需要再拉取（约 200 字节）。
 *
 *   term u32 | seq u64 | chainTime u64 | result u8 | bytes(op) | hash32(sigHash)
 *   | bool(pledgeExists) | str(pledgeAssetId) | u64(pledgeAmount) | hash32(execHash)
 *
 *   execHash = SHA3-256("QNS-EXEC" || prevExecHash || 上面 execHash 之前的全部字节)
 *
 * 帧里不带 prevExecHash：接收方用自己本地上一帧的 execHash 重算并比对，
 * 这一步本身就是连续性校验。签名本体不在帧里（ML-DSA-87 签名 4627 字节），
 * 推送时随帧附带（FramePacket），落盘时单独存放，帧里只留 sigHash。
 */
public final class NameFrame {

    static final byte[] EXEC_DOMAIN    = "QNS-EXEC".getBytes(StandardCharsets.US_ASCII);
    static final byte[] GENESIS_DOMAIN = "QNS-GENESIS".getBytes(StandardCharsets.US_ASCII);

    public final int     term;
    public final long    seq;
    public final long    chainTime;
    public final int     result;
    public final byte[]  opBytes;
    public final byte[]  sigHash;
    public final boolean pledgeExists;
    public final String  pledgeAssetId;
    public final long    pledgeAmount;
    public final byte[]  execHash;

    private NameOp op;   // 惰性解析

    public NameFrame(int term, long seq, long chainTime, int result, byte[] opBytes, byte[] sigHash,
                     boolean pledgeExists, String pledgeAssetId, long pledgeAmount, byte[] execHash) {
        if (term < 0) throw new IllegalArgumentException("term 不能为负");
        if (seq < 1) throw new IllegalArgumentException("seq 从 1 开始");
        if (result < 0 || result > 255) throw new IllegalArgumentException("result 必须是 u8");
        if (sigHash == null || sigHash.length != Sha3.HASH_LEN) throw new IllegalArgumentException("sigHash 必须 32 字节");
        if (execHash == null || execHash.length != Sha3.HASH_LEN) throw new IllegalArgumentException("execHash 必须 32 字节");
        if (pledgeAssetId == null) throw new IllegalArgumentException("pledgeAssetId 不能为 null，无质押时用空串");
        this.term = term; this.seq = seq; this.chainTime = chainTime; this.result = result;
        this.opBytes = opBytes.clone(); this.sigHash = sigHash.clone();
        this.pledgeExists = pledgeExists; this.pledgeAssetId = pledgeAssetId; this.pledgeAmount = pledgeAmount;
        this.execHash = execHash.clone();
    }

    /** 由输入构造一帧并计算 execHash。 */
    public static NameFrame build(int term, FrameInput in, int result, byte[] sigHash, byte[] prevExecHash) {
        byte[] op = in.op().toBytes();
        byte[] body = body(term, in.seq(), in.chainTime(), result, op, sigHash,
                in.pledgeExists(), in.pledgeAssetId(), in.pledgeAmount());
        return new NameFrame(term, in.seq(), in.chainTime(), result, op, sigHash,
                in.pledgeExists(), in.pledgeAssetId(), in.pledgeAmount(), execOf(prevExecHash, body));
    }

    private static byte[] body(int term, long seq, long chainTime, int result, byte[] op, byte[] sigHash,
                               boolean pe, String asset, long amount) {
        return new QccCanonicalWriter(op.length + 128)
                .u32(term).u64(seq).u64(chainTime).u8(result).bytes(op).hash32(sigHash)
                .bool(pe).str(asset).u64(amount)
                .toBytes();
    }

    public byte[] body() {
        return body(term, seq, chainTime, result, opBytes, sigHash, pledgeExists, pledgeAssetId, pledgeAmount);
    }

    public static byte[] execOf(byte[] prev, byte[] body) {
        return Sha3.hash(EXEC_DOMAIN, prev, body);
    }

    /** 给定上一帧 execHash，本帧的 execHash 是否正确。 */
    public boolean execMatches(byte[] prevExecHash) {
        return Sha3.equalsConstantTime(execOf(prevExecHash, body()), execHash);
    }

    /** publisher = 保留名发布者（协议交易 from），未配置 protocolTx 时为空串。 */
    public static byte[] genesisExecHash(byte[] protocolHash, String instanceId, String publisher) {
        return Sha3.hash(GENESIS_DOMAIN, protocolHash, instanceId.getBytes(StandardCharsets.UTF_8),
                new byte[]{0}, publisher.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] encode() {
        byte[] b = body();
        byte[] out = Arrays.copyOf(b, b.length + Sha3.HASH_LEN);
        System.arraycopy(execHash, 0, out, b.length, Sha3.HASH_LEN);
        return out;
    }

    public static NameFrame decode(byte[] b) {
        QccCanonicalReader r = new QccCanonicalReader(b);
        int term = (int) r.u32();
        long seq = r.u64();
        long ct = r.u64();
        int res = r.u8();
        byte[] op = r.bytes();
        byte[] sh = r.hash32();
        boolean pe = r.bool();
        String asset = r.str();
        long amount = r.u64();
        byte[] eh = r.hash32();
        r.finish();
        if (asset == null) throw new IllegalArgumentException("pledgeAssetId 为 null");
        NameFrame f = new NameFrame(term, seq, ct, res, op, sh, pe, asset, amount, eh);
        f.op();   // 立即校验 op 结构
        return f;
    }

    public NameOp op() {
        if (op == null) op = NameOp.fromBytes(opBytes);
        return op;
    }

    public FrameInput input() {
        return new FrameInput(op(), pledgeExists, pledgeAssetId, pledgeAmount, chainTime, seq);
    }

    public String execHex() { return Sha3.toHex(execHash); }

    @Override
    public String toString() {
        return "Frame{t=" + term + " seq=" + seq + " " + op().opName() + " " + op().name
                + " r=" + result + " exec=" + execHex().substring(0, 12) + "…}";
    }
}
