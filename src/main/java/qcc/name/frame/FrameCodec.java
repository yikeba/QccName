package qcc.name.frame;

import qcc.name.codec.QccCanonicalReader;
import qcc.name.codec.QccCanonicalWriter;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 节点间线格式，沿用 NodeCredential 的约定：
 *   MAGIC(4)="QNSF" | TYPE(1) | payloadLen(4) | payload
 *   TYPE 0x01 data      payload = bytes(frame) | bytes(signature) | bytes(pubkey，可为空)
 *        0x02 list      payload = u32(count) | data-payload × count
 *        0x03 ack       payload = str(nodeId) | u32(term) | u64(seq) | hash32(execHash)
 *        0x04 heartbeat payload = str(nodeId) | u32(term) | u64(seq) | hash32(execHash) | bool(primary)
 * 不设版本字节：语义变更必须改 MAGIC，payloadLen 自校验结构变化。
 */
public final class FrameCodec {

    public static final String MAGIC_STR = "QNSF";
    static final byte[] MAGIC = MAGIC_STR.getBytes(StandardCharsets.US_ASCII);
    public static final byte TYPE_DATA = 0x01, TYPE_LIST = 0x02, TYPE_ACK = 0x03, TYPE_HEARTBEAT = 0x04;
    static final int HEADER_LEN = 9;
    public static final int MAX_PAYLOAD = 64 * 1024 * 1024;

    private FrameCodec() {}

    // ── 编码 ──────────────────────────────────────────────────────

    public static byte[] encodeData(FramePacket p) { return envelope(TYPE_DATA, dataPayload(p)); }

    public static byte[] encodeList(List<FramePacket> list) {
        QccCanonicalWriter w = new QccCanonicalWriter(list.size() * 5000 + 8).u32(list.size());
        for (FramePacket p : list) w.bytes(dataPayload(p));
        return envelope(TYPE_LIST, w.toBytes());
    }

    public static byte[] encodeAck(Ack a) {
        return envelope(TYPE_ACK, new QccCanonicalWriter(96)
                .str(a.nodeId()).u32(a.term()).u64(a.seq()).hash32(a.execHash()).toBytes());
    }

    public static byte[] encodeHeartbeat(Heartbeat h) {
        return envelope(TYPE_HEARTBEAT, new QccCanonicalWriter(96)
                .str(h.nodeId()).u32(h.term()).u64(h.seq()).hash32(h.execHash()).bool(h.primary()).toBytes());
    }

    private static byte[] dataPayload(FramePacket p) {
        return new QccCanonicalWriter(8000).bytes(p.frame().encode()).bytes(p.signature()).bytes(p.pubkey()).toBytes();
    }

    private static byte[] envelope(byte type, byte[] payload) {
        ByteBuffer b = ByteBuffer.allocate(HEADER_LEN + payload.length);
        b.put(MAGIC).put(type).putInt(payload.length).put(payload);
        return b.array();
    }

    // ── 解码 ──────────────────────────────────────────────────────

    public static FramePacket decodeData(byte[] wire) { return dataFrom(open(wire, TYPE_DATA)); }

    public static List<FramePacket> decodeList(byte[] wire) {
        QccCanonicalReader r = new QccCanonicalReader(open(wire, TYPE_LIST));
        long n = r.u32();
        List<FramePacket> out = new ArrayList<>((int) Math.min(n, 4096));
        for (long i = 0; i < n; i++) out.add(dataFrom(r.bytes()));
        r.finish();
        return out;
    }

    public static Ack decodeAck(byte[] wire) {
        QccCanonicalReader r = new QccCanonicalReader(open(wire, TYPE_ACK));
        Ack a = new Ack(r.str(), (int) r.u32(), r.u64(), r.hash32());
        r.finish();
        return a;
    }

    public static Heartbeat decodeHeartbeat(byte[] wire) {
        QccCanonicalReader r = new QccCanonicalReader(open(wire, TYPE_HEARTBEAT));
        Heartbeat h = new Heartbeat(r.str(), (int) r.u32(), r.u64(), r.hash32(), r.bool());
        r.finish();
        return h;
    }

    private static FramePacket dataFrom(byte[] payload) {
        QccCanonicalReader r = new QccCanonicalReader(payload);
        NameFrame f = NameFrame.decode(r.bytes());
        byte[] sig = r.bytes();
        byte[] pk = r.bytes();
        r.finish();
        return new FramePacket(f, sig, pk);
    }

    private static byte[] open(byte[] wire, byte expectType) {
        if (wire == null || wire.length < HEADER_LEN) throw new IllegalArgumentException("帧过短");
        ByteBuffer b = ByteBuffer.wrap(wire);
        for (byte m : MAGIC) if (b.get() != m) throw new IllegalArgumentException("MAGIC 错误");
        byte t = b.get();
        if (t != expectType) throw new IllegalArgumentException("类型不符：期望 " + expectType + " 实际 " + t);
        int len = b.getInt();
        if (len < 0 || len > MAX_PAYLOAD) throw new IllegalArgumentException("payloadLen 非法: " + len);
        if (len != b.remaining()) throw new IllegalArgumentException("payloadLen 与实际长度不符");
        byte[] p = new byte[len];
        b.get(p);
        return p;
    }
}
