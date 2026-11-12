package qcc.name.core;

import qcc.name.codec.QccCanonicalWriter;
import qcc.name.codec.Sha3;

/**
 * execHash 逐条推进器。
 *
 * 链上协议 execHash.perOp:
 *   SHA3-256(prevExecHash || u32(opCode) || canonical(payload)
 *            || SHA3-256(signatures) || u32(resultCode) || canonical(stateDelta))
 *
 * 【协议表述缺一件事:分帧】"||" 只说了拼接,没说变长字段之间怎么分界。
 * 两个实现如果一个直接拼裸字节、一个加长度前缀,结果不同,而两边都能
 * 自圆其说地宣称"我按协议实现的"。所以这里明确:所有变长段一律走
 * QccCanonicalWriter 的 uint32-be 长度前缀,定长段(哈希)裸写。
 * 这一条应该在协议 v1.0.1 里写死 —— 见本批交付说明。
 *
 * 【为什么每条操作都算,不批量】一次 SHA3 是纳秒级,亿次也就几分钟,
 * 完全不是瓶颈。换来的是分歧发生时能定位到**具体哪一条**操作,
 * 而不是"某个 256 条的批次里有问题,自己去找"。
 */
public final class ExecHasher {

    private byte[] cur;

    public ExecHasher(byte[] genesisExecHash) {
        if (genesisExecHash == null || genesisExecHash.length != Sha3.HASH_LEN)
            throw new IllegalArgumentException("execHash0 必须是 32 字节");
        this.cur = genesisExecHash.clone();
    }

    public byte[] current()    { return cur.clone(); }
    public String currentHex() { return Sha3.toHex(cur); }

    /** 推进一步并返回新值。 */
    public byte[] advance(int opCode, byte[] payload, byte[] sigHash,
                          int resultCode, StateDelta delta) {
        byte[] preimage = new QccCanonicalWriter()
                .hash32(cur)
                .u32(opCode)
                .bytes(payload)
                .hash32(sigHash)
                .u32(resultCode)
                .bytes(delta.encode())
                .toBytes();
        cur = Sha3.hash(preimage);
        return cur.clone();
    }

    /** 纯函数版本,给验证者做单点复算用,不改变内部状态。 */
    public static byte[] step(byte[] prev, int opCode, byte[] payload, byte[] sigHash,
                              int resultCode, StateDelta delta) {
        return Sha3.hash(new QccCanonicalWriter()
                .hash32(prev).u32(opCode).bytes(payload).hash32(sigHash)
                .u32(resultCode).bytes(delta.encode()).toBytes());
    }
}
