package qcc.name.core;

import qcc.name.codec.Sha3;
import qcc.name.protocol.ProtocolLoader;
import qcc.name.protocol.ProtocolRoot;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * 确定性核心一致性向量 —— 第三批。
 *
 * 这一批直接加载**链上那份真协议**(protocolHash
 * dd6eba18d557b4c3a99d4355390021488e052c088f49465ca0f7894109dfcb51,
 * 交易 f1134cb5…,容器高度 342665),不是测试夹具。
 * 所以它同时验证了两件事:核心逻辑正确,以及协议文档确实可执行。
 *
 * 运行:
 *   java -Dstdout.encoding=UTF-8 -cp &lt;out&gt; qcc.name.core.CoreSelfTest [协议文件路径]
 * 不传路径时默认读 ./qcc-name-v1.json
 */
public class CoreSelfTest {

    private static int failed = 0;
    private static void ck(boolean c, String m) {
        if (!c) failed++;
        System.out.println((c ? "  OK   " : "  FAIL ") + m);
    }

    // 测试用地址。真实地址是 base58,这里只要求非空且唯一。
    static final String A = "QaddrAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    static final String B = "QaddrBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    static final String C = "QaddrCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

    static final long H0 = 342665L;          // 创世高度
    static long seq = 0;

    public static void main(String[] args) throws Exception {
        Path file = Path.of(args.length > 0 ? args[0] : "qcc-name-v1.json");
        byte[] payload = Files.readAllBytes(file);

        // ── 1. 加载链上协议 ────────────────────────────────────────
        System.out.println("协议文件 " + file + "  " + payload.length + " 字节");
        ProtocolRoot root = ProtocolLoader.loadFromBytes(payload, ProtocolLoader.PROTOCOL_HASH);
        ck(root.protocolHash().equals(ProtocolLoader.PROTOCOL_HASH), "protocolHash 与链上一致");
        ck(root.protocol().equals("qcc-name") && root.version().equals("1.0.0"), "协议标识与版本");
        ck(root.ops().size() == 5, "协议声明 5 个操作");
        ck(root.params().maxAddressesPerName() == 16, "参数从协议注入(maxAddressesPerName=16)");
        ck(root.antiReplayWindowBlocks() == 100, "防重放窗口从协议注入(100 个区块)");

        // 篡改一个字节必须被拒
        byte[] tampered = payload.clone();
        tampered[tampered.length - 1] ^= 0x01;
        ck(thr(() -> ProtocolLoader.loadFromBytes(tampered, ProtocolLoader.PROTOCOL_HASH)),
                "改动一个字节即拒绝加载");

        // ── 2. 创世 execHash ──────────────────────────────────────
        String instanceId = Sha3.hashUtf8Hex("tagRuleTx:qccname");
        byte[] g1 = root.genesisExecHash(instanceId, H0);
        byte[] g2 = root.genesisExecHash(instanceId, H0);
        byte[] g3 = root.genesisExecHash(instanceId, H0 + 1);
        ck(java.util.Arrays.equals(g1, g2), "execHash0 可复现");
        ck(!java.util.Arrays.equals(g1, g3), "创世高度不同则 execHash0 不同");

        // ── 3. 跑一整套操作 ────────────────────────────────────────
        NameStateMachine sm = new NameStateMachine(root, g1);
        List<OpResult> results = run(sm);

        ck(results.get(0).resultCode() == OpHandlers.OK,             "register alice 成功");
        ck(results.get(1).resultCode() == OpHandlers.NAME_TAKEN,     "重复注册 alice → nameTaken(12)");
        ck(results.get(2).resultCode() == OpHandlers.NAME_CONFUSABLE,"注册 a1ice → nameConfusable(11) 同形字拦截");
        ck(results.get(3).resultCode() == OpHandlers.NAME_FORMAT,    "注册 -bad- → nameFormat(10)");
        ck(results.get(4).resultCode() == OpHandlers.PLEDGE_MISSING, "无质押注册 → pledgeMissing(31)");
        ck(results.get(5).resultCode() == OpHandlers.OK,             "bindAddr B 成功(双签)");
        ck(results.get(6).resultCode() == OpHandlers.ADDRESS_TAKEN,  "B 再绑到别的名字 → addressTaken(20)");
        ck(results.get(7).resultCode() == OpHandlers.OK,             "transferOwner → B");
        ck(results.get(8).resultCode() == OpHandlers.TARGET_IS_OWNER,"解绑当前 owner → targetIsOwner(23)");
        ck(results.get(9).resultCode() == OpHandlers.OK,             "unbindAddr A 成功");
        ck(results.get(10).resultCode() == OpHandlers.CONFIRM_FLAG_MISSING, "release 未确认 → confirmFlagMissing(25)");
        ck(results.get(11).resultCode() == OpHandlers.OK,            "release 成功");
        ck(results.get(12).resultCode() == OpHandlers.NAME_IN_COOLDOWN, "冷却期内重注册 → nameInCooldown(13)");
        ck(results.get(13).resultCode() == OpHandlers.SIG_INVALID,   "签名无效 → sigInvalid(40)");
        ck(results.get(14).resultCode() == OpHandlers.REPLAY_WINDOW, "超出防重放窗口 → replayWindow(41)");
        ck(results.get(15).resultCode() == OpHandlers.NOT_AUTHORIZED,"签名者不匹配 → notAuthorized(42)");
        ck(results.get(16).resultCode() == OpHandlers.UNKNOWN_OP_CODE, "未知 opCode → 43");

        NameState st = sm.state();
        ck(!st.nameTaken(NameValidator.nameHash("alice")), "release 之后 alice 已释放");
        ck(st.nextIncarnation(NameValidator.nameHash("alice")) == 2, "世代号进位到 2");

        // ── 4. 确定性:同一序列跑两遍,execHash 完全相同 ────────────
        NameStateMachine sm2 = new NameStateMachine(root, root.genesisExecHash(instanceId, H0));
        seq = 0;
        List<OpResult> again = run(sm2);
        ck(sm.execHashHex().equals(sm2.execHashHex()), "同一操作序列两次执行 execHash 相同");
        ck(sm.stateRootHex().equals(sm2.stateRootHex()), "stateRoot 相同");
        for (int i = 0; i < results.size(); i++)
            if (!results.get(i).execHashHex().equals(again.get(i).execHashHex())) {
                ck(false, "第 " + (i + 1) + " 步 execHash 不一致"); break;
            }
        ck(true, "逐条 execHash 全部一致(" + results.size() + " 步)");

        // ── 5. 被拒的操作也推进 execHash ───────────────────────────
        // 这是"审查与正当拒绝可区分"的技术基础
        boolean allAdvanced = true;
        for (int i = 1; i < results.size(); i++)
            if (results.get(i).execHashHex().equals(results.get(i - 1).execHashHex()))
                allAdvanced = false;
        ck(allAdvanced, "每一步(含被拒的)都推进了 execHash");
        long rejected = results.stream().filter(r -> !r.ok()).count();
        ck(rejected > 0 && results.stream().filter(r -> !r.ok())
                .allMatch(r -> r.delta().isEmpty()), "被拒操作产生空 delta(" + rejected + " 条)");

        // ── 6. 单点复算:验证者能独立验证任意一步 ──────────────────
        byte[] prev = results.get(4).execHash();
        OpResult step6 = results.get(5);
        byte[] recomputed = ExecHasher.step(prev, 2,
                OpHandlers.nameAndAddr("alice", B), sig(true),
                step6.resultCode(), step6.delta());
        ck(java.util.Arrays.equals(recomputed, step6.execHash()),
                "任意一步可被独立复算(无需重放全部历史)");

        System.out.println();
        System.out.println("最终 execHash  " + sm.execHashHex());
        System.out.println("最终 stateRoot " + sm.stateRootHex());
        System.out.println("状态           " + sm.state());
        System.out.println();
        System.out.println(failed == 0 ? "全部通过" : failed + " 项失败");
        if (failed != 0) System.exit(1);
    }

    // ── 操作序列 ──────────────────────────────────────────────────

    private static List<OpResult> run(NameStateMachine sm) {
        seq = 0;
        PledgeFact good = new PledgeFact(true, "QCC", 1_000_000_000L);
        PledgeFact poor = PledgeFact.none();
        long h = H0 + 10;

        return List.of(
            sm.apply(op(1, OpHandlers.nameAndAddr("alice", A), List.of(A), h, h, true, good)),
            sm.apply(op(1, OpHandlers.nameAndAddr("alice", B), List.of(B), h, h, true, good)),
            sm.apply(op(1, OpHandlers.nameAndAddr("a1ice", B), List.of(B), h, h, true, good)),
            sm.apply(op(1, OpHandlers.nameAndAddr("-bad-", B), List.of(B), h, h, true, good)),
            sm.apply(op(1, OpHandlers.nameAndAddr("carol", C), List.of(C), h, h, true, poor)),
            sm.apply(op(2, OpHandlers.nameAndAddr("alice", B), List.of(A, B), h, h, true, poor)),
            sm.apply(op(1, OpHandlers.nameAndAddr("dave",  B), List.of(B), h, h, true, good)),
            sm.apply(op(4, OpHandlers.nameAndAddr("alice", B), List.of(A), h, h, true, poor)),
            sm.apply(op(3, OpHandlers.nameAndAddr("alice", B), List.of(B), h, h, true, poor)),
            sm.apply(op(3, OpHandlers.nameAndAddr("alice", A), List.of(B), h, h, true, poor)),
            sm.apply(op(5, OpHandlers.nameAndFlag("alice", false), List.of(B), h, h, true, poor)),
            sm.apply(op(5, OpHandlers.nameAndFlag("alice", true),  List.of(B), h, h, true, poor)),
            sm.apply(op(1, OpHandlers.nameAndAddr("alice", C), List.of(C), h, h, true, good)),
            sm.apply(op(1, OpHandlers.nameAndAddr("erin",  C), List.of(C), h, h, false, good)),
            sm.apply(op(1, OpHandlers.nameAndAddr("frank", C), List.of(C), h, h + 500, true, good)),
            sm.apply(op(1, OpHandlers.nameAndAddr("grace", C), List.of(A), h, h, true, good)),
            sm.apply(op(9, OpHandlers.nameAndAddr("henry", C), List.of(C), h, h, true, good))
        );
    }

    private static OpInput op(int code, byte[] payload, List<String> signers,
                              long blockHeight, long admitHeight, boolean sigValid, PledgeFact p) {
        return new OpInput(code, blockHeight, admitHeight, payload, signers,
                sig(sigValid), sigValid, ++seq, p);
    }

    /** 测试里签名本体不存在,只用一个稳定的 sigHash 占位。 */
    private static byte[] sig(boolean v) { return Sha3.hashUtf8("sig-" + v); }

    private static boolean thr(Runnable r) {
        try { r.run(); return false; } catch (Exception e) { return true; }
    }
}
