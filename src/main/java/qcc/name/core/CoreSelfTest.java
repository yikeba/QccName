package qcc.name.core;

import qcc.name.Check;
import qcc.name.codec.Sha3;
import qcc.name.frame.NameFrame;
import qcc.name.op.*;
import qcc.name.protocol.NameProtocol;
import qcc.name.protocol.ProtocolLoader;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 确定性核心：逐项检查、结果码顺序、状态变更、execHash 可复现。
 * 不涉及签名（核心不验签），帧的 sigHash 用一个固定值代替。
 */
public final class CoreSelfTest {

    static final String C = "6666";
    static final String A = "QWasmDyBQzCTdUhj6NLyfAzU6z5sTSdhM1", B = "QMnGE6bPBkvE6M2Dp28V8sTXo8bs5nTHy4";
    static final String H1 = "11".repeat(32), H2 = "22".repeat(32);
    static final byte[] SIG = Sha3.hashUtf8("sig");
    static final long DAY = 86_400_000L;

    NameMachine m;
    final List<NameFrame> log = new ArrayList<>();
    long t = 1_793_500_000_000L;

    CoreSelfTest(NameProtocol p) { m = new NameMachine(p, "core-test"); }

    int eval(NameOp op, boolean pledge, long amount) {
        return m.evaluate(new FrameInput(op, pledge, pledge ? "QCC" : "", amount, t, m.lastSeq() + 1));
    }

    /** 评估并在可写入日志时写入，返回结果码。 */
    int put(NameOp op, boolean pledge, long amount) {
        FrameInput in = new FrameInput(op, pledge, pledge ? "QCC" : "", amount, t, m.lastSeq() + 1);
        int code = m.evaluate(in);
        if (m.loggable(op, code)) {
            NameFrame f = NameFrame.build(0, in, code, op.userSigned() ? SIG : Sha3.zero32(), m.execHash());
            m.apply(f);
            log.add(f);
        }
        return code;
    }

    RegisterOp reg(String addr, String name, String cred) { return new RegisterOp(C, addr, name, ++t, cred); }

    public static int run(String[] args) {
        Check c = new Check();
        NameProtocol p = ProtocolLoader.loadFile(Path.of("testdata/qcc-name-test-v1.0.0.json"), null);
        CoreSelfTest x = new CoreSelfTest(p);
        long Q = 1_000_000_000L;

        c.ck(x.put(x.reg(A, "alice.qcc", H1), true, Q) == 0, "注册 alice.qcc → OK");
        c.ck(x.m.state().record("alice.qcc").regSeq() == 1, "regSeq = 1");
        c.ck(x.eval(x.reg(B, "alice.qcc", H2), true, Q) == ResultCode.NAME_TAKEN, "他人注册同名 → 13 nameTaken");
        c.ck(x.eval(x.reg(B, "a1ice.qcc", H2), true, Q) == ResultCode.CONFUSABLE, "a1ice.qcc → 12 同形字");
        c.ck(x.eval(x.reg(B, "alice.osn", H2), true, Q) == 0, "alice.osn（不同 tag）→ 可注册");
        c.ck(x.eval(x.reg(B, "admin.qcc", H2), true, Q) == 0, "协议不内置保留名：admin.qcc 可注册（先到先得）");
        reservedTests(c, p, Q);
        c.ck(x.eval(x.reg(B, "b.qcc", H2), true, Q) == ResultCode.LABEL_FORMAT, "1 字符 → 10 格式");
        c.ck(x.eval(x.reg(B, "a".repeat(33) + ".qcc", H2), true, Q) == ResultCode.LABEL_FORMAT, "33 字符 → 10 格式");
        c.ck(x.eval(x.reg(B, "-bob.qcc", H2), true, Q) == ResultCode.LABEL_FORMAT, "首字符 - → 10 格式");
        c.ck(x.eval(x.reg(B, "bob.xyz", H2), true, Q) == ResultCode.TAG_NOT_OPEN, "未开放的 tag → 15");
        c.ck(x.eval(x.reg(B, "bob.qcc", H2), true, Q - 1) == ResultCode.PLEDGE_NOT_MET, "质押 1 QCC - 1 → 30");
        c.ck(x.eval(x.reg(B, "bob.qcc", H2), false, 0) == ResultCode.PLEDGE_NOT_MET, "无质押 → 30");
        c.ck(x.eval(x.reg(A, "alice2.qcc", H1), true, Q) == ResultCode.ADDRESS_HAS_NAME, "同地址同 tag 第二个名字 → 20");
        c.ck(x.eval(x.reg(A, "alice.osn", H1), true, Q) == 0, "同地址不同 tag → 可注册");
        c.ck(x.eval(x.reg(B, "admin.qcc", H2), false, 0) == ResultCode.PLEDGE_NOT_MET,
                "无质押的请求 → 30（质押先于业务检查，日志中的拒绝必有质押成本）");
        c.ck(!x.m.loggable(x.reg(B, "bob.qcc", H2), ResultCode.PLEDGE_NOT_MET), "30 不进日志");
        c.ck(x.m.loggable(x.reg(B, "bob.qcc", H2), ResultCode.NAME_TAKEN), "13 进日志");

        // 被记录的拒绝也推进 lastTs
        RegisterOp taken = x.reg(B, "alice.qcc", H2);
        c.ck(x.put(taken, true, Q) == ResultCode.NAME_TAKEN && x.m.lastSeq() == 2, "nameTaken 写入日志（seq=2）");
        c.ck(x.m.state().lastTs(B) == taken.timestamp, "拒绝帧也推进 lastTs");
        c.ck(x.eval(new RegisterOp(C, B, "bob.qcc", taken.timestamp, H2), true, Q) == ResultCode.TS_NOT_MONOTONIC,
                "同一 timestamp 再提交 → 21");

        // 删除
        c.ck(x.eval(new UnregisterOp(C, A, "alice.qcc", ++x.t, 9), false, 0) == ResultCode.REGSEQ_MISMATCH, "regSeq 错误 → 42");
        c.ck(x.eval(new UnregisterOp(C, B, "alice.qcc", ++x.t, 1), false, 0) == ResultCode.HOLDER_MISMATCH, "非持有者删除 → 41");
        c.ck(x.eval(new UnregisterOp(C, A, "nobody.qcc", ++x.t, 1), false, 0) == ResultCode.NAME_NOT_FOUND, "删除不存在的名字 → 40");
        UnregisterOp un = new UnregisterOp(C, A, "alice.qcc", ++x.t, 1);
        c.ck(x.put(un, false, 0) == 0 && x.m.state().record("alice.qcc") == null, "持有者删除 → OK，记录移除");
        c.ck(x.m.state().confusableOwner("qcc|alice") == null, "同形字索引一并移除");
        c.ck(x.eval(un, false, 0) == ResultCode.TS_NOT_MONOTONIC, "重放同一条删除 → 21");

        // 冷却期：任何人含原地址
        c.ck(x.eval(x.reg(A, "alice.qcc", H1), true, Q) == ResultCode.COOLDOWN, "原地址冷却期内重注册 → 14");
        c.ck(x.eval(x.reg(B, "alice.qcc", H2), true, Q) == ResultCode.COOLDOWN, "他人冷却期内注册 → 14");
        c.ck(x.eval(x.reg(B, "a1ice.qcc", H2), true, Q) == 0, "冷却期只锁原名，形近名已无冲突");
        c.ck(x.eval(x.reg(A, "anna.qcc", H1), true, Q) == 0, "删除后地址可立即注册别的名字");
        x.t += 30 * DAY;
        c.ck(x.put(x.reg(B, "alice.qcc", H2), true, Q) == 0, "30 天后 → 他人可注册");
        c.ck(x.m.state().tomb("alice.qcc") == null, "重新注册后墓碑移除");

        // expire
        NameRecord rb = x.m.state().record("alice.qcc");
        c.ck(x.eval(new ExpireOp(C, B, "alice.qcc", x.t, H2), true, Q) == ResultCode.PLEDGE_STILL_VALID, "质押仍在 → 44，不能回收");
        c.ck(x.eval(new ExpireOp(C, B, "alice.qcc", x.t, H1), false, 0) == ResultCode.CREDENTIAL_MISMATCH, "凭证不符 → 43");
        c.ck(x.put(new ExpireOp(C, B, "alice.qcc", x.t, H2), false, 0) == 0 && x.m.state().record("alice.qcc") == null,
                "质押已撤销 → expire OK");
        c.ck(x.m.state().tomb("alice.qcc").regSeq() == rb.regSeq(), "expire 写墓碑");

        // 确定性：同一份日志在另一台"机器"上重放结果完全一致
        NameMachine m2 = new NameMachine(p, "core-test");
        for (NameFrame f : x.log) m2.apply(NameFrame.decode(f.encode()));
        c.ck(m2.execHex().equals(x.m.execHex()) && m2.state().digest().equals(x.m.state().digest()),
                "独立重放 " + x.log.size() + " 帧：execHash 与状态摘要一致");

        NameMachine m3 = new NameMachine(p, "another-instance");
        c.ck(c.throwsAny(() -> m3.apply(x.log.get(0))), "不同 instanceId 的创世 → execHash 分歧被发现");

        NameFrame f0 = x.log.get(0);
        NameFrame forged = new NameFrame(f0.term, f0.seq, f0.chainTime, ResultCode.NAME_TAKEN, f0.opBytes, f0.sigHash,
                f0.pledgeExists, f0.pledgeAssetId, f0.pledgeAmount, f0.execHash);
        c.ck(c.throwsAny(() -> new NameMachine(p, "core-test").apply(forged)), "篡改结果码 → 重放发现分歧");
        NameFrame noPledge = NameFrame.build(0, new FrameInput(f0.op(), false, "", 0, f0.chainTime, 1),
                ResultCode.OK, f0.sigHash, NameFrame.genesisExecHash(p.protocolHashBytes(), "core-test", ""));
        c.ck(c.throwsAny(() -> new NameMachine(p, "core-test").apply(noPledge)), "无质押却记为 OK → 重放拒绝");
        return c.failed();
    }

    // ── Reserved ────────────────────────────────────────────────────

    static final String TX1 = "a1".repeat(32), TX2 = "a2".repeat(32), TX3 = "a3".repeat(32);

    static byte[] doc(NameProtocol p, long seq, String prev, String names, String release) {
        return ("{\n  \"protocol\": \"qcc-name-reserved\",\n  \"version\": \"1.0.0\",\n  \"nameProtocolHash\": \"" + p.protocolHash
                + "\",\n  \"seq\": " + seq + ",\n  \"prevTx\": \"" + prev + "\",\n  \"names\": {" + names + "},\n  \"release\": [" + release + "]\n}\n")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    ReserveOp rsv(String from, String chain, String tx, long height, byte[] d) { return new ReserveOp(chain, from, ++t, tx, height, d); }

    static void reservedTests(Check c, NameProtocol base, long Q) {
        NameProtocol p = base.withReservedPublisher(A);
        CoreSelfTest y = new CoreSelfTest(p);
        c.ck(y.put(y.reg(B, "admin.osn", H2), true, Q) == 0, "Reserved 生效前：B 注册 admin.osn → OK");
        byte[] d1 = doc(p, 1, "", "\"admin.osn\": \"" + A + "\", \"security.osn\": \"\"", "");

        c.ck(y.put(y.rsv(B, C, TX1, 100, d1), false, 0) == ResultCode.RESERVE_PUBLISHER, "非发布者发布 → 50");
        c.ck(y.put(y.rsv(A, "9999", TX1, 100, d1), false, 0) == ResultCode.RESERVE_CHAIN, "chain 不符 → 51");
        c.ck(y.put(y.rsv(A, C, TX1, 100, doc(base.withReservedPublisher(B), 1, "", "\"x.osn\": \"\"", "")), false, 0) == ResultCode.RESERVE_DOCUMENT,
                "label 不合规（1 字符）→ 52");
        c.ck(y.put(y.rsv(A, C, TX1, 100, doc(p, 1, "", "\"admin.xyz\": \"\"", "")), false, 0) == ResultCode.RESERVE_DOCUMENT, "未声明的 tag → 52");
        c.ck(y.put(y.rsv(A, C, TX1, 100, "{\"protocol\":1}".getBytes()), false, 0) == ResultCode.RESERVE_DOCUMENT, "文档结构错误 → 52");
        c.ck(y.put(y.rsv(A, C, TX1, 100, doc(p, 2, "", "", "")), false, 0) == ResultCode.RESERVE_SEQ, "首版 seq=2 → 53");
        c.ck(y.put(y.rsv(A, C, TX1, 100, doc(p, 1, TX3, "", "")), false, 0) == ResultCode.RESERVE_SEQ, "首版 prevTx 非空 → 53");
        long before = y.m.lastSeq();
        c.ck(y.m.lastSeq() == before && y.m.state().reservedSeq() == 0, "被拒的 reserve 不进日志");

        c.ck(y.put(y.rsv(A, C, TX1, 100, d1), false, 0) == 0, "发布者首版 → OK");
        NameState st = y.m.state();
        c.ck(A.equals(st.reservedAddress("admin.osn")) && "".equals(st.reservedAddress("security.osn")), "表生效：admin.osn → A，security.osn 保留不绑定");
        c.ck(st.record("admin.osn") == null && st.tomb("admin.osn") != null && st.holderName("osn", B) == null,
                "已注册的同名 admin.osn 被移除并进入冷却期，B 的 holder 释放");
        c.ck(y.eval(y.reg(A, "admin.osn", H1), true, Q) == ResultCode.RESERVED, "表中名字不能注册 → 11（含指定地址本身）");
        c.ck(y.eval(y.reg(B, "adrnin.osn", H2), true, Q) == ResultCode.RESERVED, "与保留名形近 adrnin.osn（rn≈m）→ 11");
        c.ck(y.eval(y.reg(B, "security.osn", H2), true, Q) == ResultCode.RESERVED, "保留不绑定的 security.osn → 11");
        c.ck(y.eval(y.reg(B, "admin.qcc", H2), true, Q) == 0, "其他 tag 不受影响：admin.qcc → OK");
        c.ck(st.reservedSeq() == 1 && TX1.equals(st.reservedTx()) && st.reservedHeight() == 100, "当前版本 seq=1 tx1 高度 100");

        byte[] d2drop = doc(p, 2, TX1, "\"admin.osn\": \"" + B + "\"", "");
        c.ck(y.put(y.rsv(A, C, TX2, 200, d2drop), false, 0) == ResultCode.RESERVE_DROPS_NAME, "去掉 security.osn 却未写 release → 55");
        byte[] d2 = doc(p, 2, TX1, "\"admin.osn\": \"" + B + "\"", "\"security.osn\"");
        c.ck(y.put(y.rsv(A, C, TX2, 100, d2), false, 0) == ResultCode.RESERVE_HEIGHT, "高度未递增 → 54");
        c.ck(y.put(y.rsv(A, C, TX2, 200, doc(p, 2, TX3, "\"admin.osn\": \"" + B + "\"", "\"security.osn\"")), false, 0) == ResultCode.RESERVE_SEQ,
                "prevTx 不是上一版 → 53");
        c.ck(y.put(y.rsv(A, C, TX2, 200, doc(p, 2, TX1, "\"admin.osn\": \"" + B + "\"", "\"nobody.osn\"")), false, 0) == ResultCode.RESERVE_DROPS_NAME,
                "release 不在上一版中 → 55");
        c.ck(y.put(y.rsv(A, C, TX2, 200, d2), false, 0) == 0, "第 2 版（admin 换成 B，释放 security）→ OK");
        c.ck(B.equals(st.reservedAddress("admin.osn")) && st.reservedAddress("security.osn") == null, "admin.osn 立即切到 B；security.osn 退出表");
        c.ck(y.eval(y.reg(B, "security.osn", H2), true, Q) == 0, "release 后 security.osn 重新开放注册");
        c.ck(y.put(y.rsv(A, C, TX2, 300, d2), false, 0) == ResultCode.RESERVE_SEQ, "重放第 2 版 → 53");
        c.ck(st.reservedHistory().size() == 2 && st.reservedHistory().get(0).height() == 100, "历史保留两版，按 seq 排序");

        NameMachine r = new NameMachine(p, "core-test");
        for (NameFrame f : y.log) r.apply(NameFrame.decode(f.encode()));
        c.ck(r.execHex().equals(y.m.execHex()) && r.state().digest().equals(y.m.state().digest()),
                "Reserved 日志独立重放：execHash 与状态摘要一致");
        c.ck(c.throwsAny(() -> new NameMachine(base, "core-test").apply(y.log.get(0))), "发布者不同（未配置 protocolTx）→ 创世 execHash 分歧");

        // 企业 tag（registration = reserved）：不开放注册，名字只来自 Reserved
        c.ck(y.eval(y.reg(B, "bob.corp", H2), true, Q) == ResultCode.TAG_NOT_OPEN, "企业 tag：自助注册 bob.corp → 15");
        byte[] d3 = doc(p, 3, TX2, "\"admin.osn\": \"" + B + "\", \"ceo.corp\": \"" + A + "\"", "");
        c.ck(y.put(y.rsv(A, C, TX3, 300, d3), false, 0) == 0 && A.equals(st.reservedAddress("ceo.corp")),
                "企业 tag：发布者在 Reserved 中分配 ceo.corp → A");

        CoreSelfTest z = new CoreSelfTest(base);
        c.ck(z.put(z.rsv(A, C, TX1, 100, d1), false, 0) == ResultCode.RESERVE_PUBLISHER, "未配置 protocolTx：任何 reserve → 50");
        c.ck(c.throwsAny(() -> base.withReservedPublisher("Qbad")), "发布者地址非法 → 拒绝");
    }

    public static void main(String[] args) { if (run(args) != 0) System.exit(1); }
}
