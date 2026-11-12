package qcc.name;

import qcc.name.codec.Sha3;
import qcc.name.core.*;
import qcc.name.protocol.*;
import qcc.name.state.*;
import java.nio.file.*;
import java.util.*;

/**
 * epoch 一致性向量 —— 第六批。
 *
 * 重点在三处:
 *   - 封口边界是日志内容的纯函数(不依赖检查发生的时刻)
 *   - epoch 链接的四条校验缺一不可
 *   - opsRoot 用 seq 定位而不是内容哈希 —— 否则内容相同的两条操作会撞叶子
 *
 * 运行: java -Dstdout.encoding=UTF-8 -cp <out> qcc.name.epoch.EpochSelfTest [协议文件]
 */
public class EpochSelfTest {

    private static int failed = 0;
    private static void ck(boolean c, String m) {
        if (!c) failed++;
        System.out.println((c ? "  OK   " : "  FAIL ") + m);
    }
    private static boolean thr(Runnable r) { try { r.run(); return false; } catch (Exception e) { return true; } }

    static final String PH = "17c8e84945ea073868143febacba50483b7adf6a4f93125b717d83f3edd6f423";
    static final String IN = "a9cabae245a9595bd937775e7441a632d8de518fad6fb404a097a8b745dafde7";
    static final String SIGNER = "QMnGE6bPBkvE6M2Dp28V8sTXo8bs5nTHy4";
    static final long H0 = 342669L;

    public static int run(String[] args) throws Exception {
        failed = 0; body(args); return failed;
    }
    public static void main(String[] args) throws Exception {
        if (run(args) != 0) System.exit(1);
    }

    private static void body(String[] args) throws Exception {
        Path file = Path.of(args.length > 0 ? args[0] : "qcc-name-v1.json");
        ProtocolRoot root = ProtocolLoader.loadFromBytes(
                Files.readAllBytes(file), ProtocolLoader.PROTOCOL_HASH);

        // ── 封口判定 ──────────────────────────────────────────────
        Path dir = Files.createTempDirectory("epoch");
        OpLogStore log = new OpLogStore(dir);
        Map<Long, Long> heights = new TreeMap<>();

        EpochBuilder b = new EpochBuilder(PH, IN, 8, 100);   // 小参数便于测试
        ck(b.shouldClose(log, s -> 0) == -1, "空日志不封口");

        // 高度全在同一个 100 区间内,不到 8 条 → 不封口
        for (int i = 1; i <= 5; i++) { long s = log.append(op(i)); heights.put(s, H0 + 10); }
        ck(b.shouldClose(log, heights::get) == -1, "5 条且未跨高度边界 → 不封口");

        // 攒够 8 条 → 精确切在第 8 条
        for (int i = 6; i <= 12; i++) { long s = log.append(op(i)); heights.put(s, H0 + 10); }
        ck(b.shouldClose(log, heights::get) == 8, "攒够 8 条 → 切在 seq=8,不是 seq=12");

        // 封口
        List<byte[]> ops = new ArrayList<>();
        for (long s = 1; s <= 8; s++) ops.add(log.read(s));
        NameState st = new NameState();
        EpochHeader e1 = b.close(8, H0 + 10, ops, st, Sha3.hashUtf8("exec1"), SIGNER);
        ck(e1.epochId() == 1 && e1.startSeq() == 1 && e1.endSeq() == 8, "epoch#1 区间 1..8");
        ck(e1.opCount() == 8, "opCount = 8");
        ck(EpochHeader.ZERO_HASH.equals(e1.prevEpochHash()), "首个 epoch 的 prevEpochHash 为全零");
        ck(b.nextStartSeq() == 9, "下一个 epoch 从 seq=9 开始");

        // 跨高度边界触发
        heights.put(13L, H0 + 200);   // 342665+10 → 342865,跨过 3428xx 的 100 边界
        log.append(op(13));
        long end = b.shouldClose(log, heights::get);
        ck(end == 13, "跨过高度边界 → 封口到 seq=13(实际 " + end + ")");

        // 边界判定与"何时检查"无关 —— 同样的日志,任何时候算都一样
        EpochBuilder b2 = new EpochBuilder(PH, IN, 8, 100);
        ck(b2.shouldClose(log, heights::get) == 8, "同一份日志,新建 builder 算出相同边界");

        // ── epoch 链接 ────────────────────────────────────────────
        List<byte[]> ops2 = new ArrayList<>();
        for (long s = 9; s <= 13; s++) ops2.add(log.read(s));
        EpochHeader e2 = b.close(13, H0 + 200, ops2, st, Sha3.hashUtf8("exec2"), SIGNER);
        ck(e2.linksTo(e1), "epoch#2 正确链接到 #1");
        ck(e1.linksTo(null), "epoch#1 链接到 null(创世)成立");
        ck(!e2.linksTo(null), "epoch#2 不能声称自己是创世");

        // 四条校验逐个破坏,都必须被发现
        ck(!tamper(e2, e1, "epochId"),   "epochId 不连续 → 链接失败");
        ck(!tamper(e2, e1, "prevHash"),  "prevEpochHash 对不上 → 链接失败");
        ck(!tamper(e2, e1, "seq"),       "seq 有缝 → 链接失败");
        ck(!tamper(e2, e1, "height"),    "endBlockHeight 倒退 → 链接失败");
        ck(!tamper(e2, e1, "instance"),  "instanceId 不同 → 链接失败");

        // ── epochHash 与编码 ──────────────────────────────────────
        ck(e1.epochHash().equals(EpochHeader.decodeUnsigned(e1.encodeUnsigned()).epochHash()),
                "header 编码往返后 epochHash 不变");
        ck(!e1.epochHash().equals(e2.epochHash()), "不同 epoch 的 hash 不同");

        // ── opsRoot 用 seq 定位 ───────────────────────────────────
        // 两条内容完全相同的操作,必须落在不同叶子上。
        // 如果用内容哈希做位置,它们会撞成一个叶子,第二条就"消失"了。
        byte[] same = op(99);
        List<byte[]> dup = List.of(same, same, same);
        byte[] rootDup = EpochBuilder.opsRoot(dup, 100);
        ck(!Arrays.equals(rootDup, EpochBuilder.opsRoot(List.of(same), 100)),
                "三条相同内容的操作 ≠ 一条(seq 定位生效,不会撞叶子)");

        // 操作包含证明
        MerkleProof p = EpochBuilder.proveOp(ops, 1, 5);
        ck(p.provesPresence()
                        && p.verify(EpochBuilder.opsRoot(ops, 1), EpochBuilder.opLeafValue(5, log.read(5))),
                "seq=5 的操作包含证明可验(" + p.sizeBytes() + " 字节)");

        // 不在本 epoch 内的 seq → 不存在证明
        MerkleProof pn = EpochBuilder.proveOp(ops, 1, 999);
        ck(pn.provesAbsence() && pn.verify(EpochBuilder.opsRoot(ops, 1), null),
                "本 epoch 外的 seq → 不存在证明可验");

        // ── 参数校验 ──────────────────────────────────────────────
        ck(thr(() -> new EpochBuilder(PH, IN, 0, 100)), "maxOpsPerEpoch=0 被拒绝");
        ck(thr(() -> new EpochHeader(PH, IN, 0, EpochHeader.ZERO_HASH, 1, 1, 1,
                PH, PH, PH, SIGNER)), "epochId=0 被拒绝");
        ck(thr(() -> new EpochHeader(PH, IN, 1, EpochHeader.ZERO_HASH, 5, 1, 1,
                PH, PH, PH, SIGNER)), "endSeq < startSeq 被拒绝");

        System.out.println();
        System.out.println("epoch#1  " + e1);
        System.out.println("epoch#2  " + e2);
        System.out.println();
        System.out.println(failed == 0 ? "全部通过" : failed + " 项失败");
    }

    /** 破坏 e2 的某个字段,返回 linksTo(e1) 的结果 —— 应该全是 false。 */
    private static boolean tamper(EpochHeader e2, EpochHeader e1, String what) {
        EpochHeader bad = switch (what) {
            case "epochId"  -> rebuild(e2, e2.epochId() + 1, e2.prevEpochHash(), e2.startSeq(), e2.endBlockHeight(), e2.instanceId());
            case "prevHash" -> rebuild(e2, e2.epochId(), Sha3.hashUtf8Hex("x"), e2.startSeq(), e2.endBlockHeight(), e2.instanceId());
            case "seq"      -> rebuild(e2, e2.epochId(), e2.prevEpochHash(), e2.startSeq() + 1, e2.endBlockHeight(), e2.instanceId());
            case "height"   -> rebuild(e2, e2.epochId(), e2.prevEpochHash(), e2.startSeq(), e1.endBlockHeight() - 1, e2.instanceId());
            case "instance" -> rebuild(e2, e2.epochId(), e2.prevEpochHash(), e2.startSeq(), e2.endBlockHeight(), Sha3.hashUtf8Hex("other"));
            default -> throw new IllegalArgumentException(what);
        };
        return bad.linksTo(e1);
    }

    private static EpochHeader rebuild(EpochHeader e, long id, String prev, long start, long h, String inst) {
        return new EpochHeader(e.protocolHash(), inst, id, prev, start,
                Math.max(start, e.endSeq()), h, e.opsRoot(), e.stateRoot(), e.execHash(), e.signerAddress());
    }

    private static byte[] op(int n) {
        return new OpInput(1, H0, H0, OpHandlers.registerPayload("name" + n,
                "Qaddr" + n, Sha3.hashUtf8Hex("cred")), List.of("Qaddr" + n),
                Sha3.hashUtf8("sig"), true, 1, PledgeFact.none()).encodeForLog();
    }
}