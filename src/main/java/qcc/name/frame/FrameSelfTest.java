package qcc.name.frame;

import qcc.name.Check;
import qcc.name.codec.Sha3;
import qcc.name.core.FrameInput;
import qcc.name.op.RegisterOp;

import java.util.List;

/** 帧与线格式的编解码。 */
public final class FrameSelfTest {

    public static int run(String[] args) {
        Check c = new Check();
        RegisterOp op = new RegisterOp("6666", "QWasmDyBQzCTdUhj6NLyfAzU6z5sTSdhM1", "alice.qcc", 1793508092990L,
                "bf7f592233113e7a3a014be4de962b7179ddefcd70e4e0df5e9267d0082c9a2d");
        byte[] sig = new byte[4627];
        sig[0] = 7;
        NameFrame f = NameFrame.build(3, new FrameInput(op, true, "QCC", 1_000_000_000L, 1793508096169L, 1),
                0, Sha3.hash(sig), Sha3.zero32());
        byte[] enc = f.encode();
        c.ck(enc.length < 260, "单帧 " + enc.length + " 字节（不含签名）");
        NameFrame d = NameFrame.decode(enc);
        c.ck(java.util.Arrays.equals(d.encode(), enc) && d.execMatches(Sha3.zero32()), "帧往返一致，execHash 可复算");
        c.ck(!d.execMatches(Sha3.hashUtf8("other")), "prevExecHash 不同 → execHash 不符");

        FramePacket p = new FramePacket(f, sig);
        FramePacket p2 = FrameCodec.decodeData(FrameCodec.encodeData(p));
        c.ck(java.util.Arrays.equals(p2.frame().encode(), enc) && java.util.Arrays.equals(p2.signature(), sig), "data 线格式往返");
        List<FramePacket> l = FrameCodec.decodeList(FrameCodec.encodeList(List.of(p, p)));
        c.ck(l.size() == 2, "list 线格式往返");
        Ack a = FrameCodec.decodeAck(FrameCodec.encodeAck(new Ack("name1", 3, 1, f.execHash)));
        c.ck(a.nodeId().equals("name1") && a.seq() == 1 && java.util.Arrays.equals(a.execHash(), f.execHash), "ack 线格式往返");
        Heartbeat h = FrameCodec.decodeHeartbeat(FrameCodec.encodeHeartbeat(new Heartbeat("name0", 3, 9, f.execHash, true)));
        c.ck(h.primary() && h.term() == 3 && h.seq() == 9, "heartbeat 线格式往返");

        byte[] w = FrameCodec.encodeData(p);
        byte[] badMagic = w.clone(); badMagic[0] = 'X';
        c.ck(c.throwsAny(() -> FrameCodec.decodeData(badMagic)), "MAGIC 错误 → 拒绝");
        c.ck(c.throwsAny(() -> FrameCodec.decodeAck(w)), "类型不符 → 拒绝");
        c.ck(c.throwsAny(() -> FrameCodec.decodeData(java.util.Arrays.copyOf(w, w.length - 1))), "截断 → 拒绝");
        byte[] extra = java.util.Arrays.copyOf(enc, enc.length + 1);
        c.ck(c.throwsAny(() -> NameFrame.decode(extra)), "帧尾部多余字节 → 拒绝");
        return c.failed();
    }

    public static void main(String[] args) { if (run(args) != 0) System.exit(1); }
}
