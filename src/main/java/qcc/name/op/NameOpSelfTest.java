package qcc.name.op;

import qcc.name.codec.Sha3;

/**
 * NameOp 一致性向量。签名字符串向量是给客户端（Flutter）对照用的：
 * 客户端拼出的字符串必须与这里逐字节一致。
 *
 * 运行：java -Dstdout.encoding=UTF-8 -cp <out> qcc.name.op.NameOpSelfTest
 */
public class NameOpSelfTest {

    private static int failed = 0;

    private static void ck(boolean cond, String msg) {
        if (!cond) failed++;
        System.out.println((cond ? "  OK   " : "  FAIL ") + msg);
    }

    private static boolean throwsIAE(Runnable r) {
        try { r.run(); return false; } catch (IllegalArgumentException e) { return true; }
    }

    public static int run(String[] args) {
        failed = 0;
        body();
        return failed;
    }

    public static void main(String[] args) {
        if (run(args) != 0) System.exit(1);
    }

    static final String ADDR = "QWasmDyBQzCTdUhj6NLyfAzU6z5sTSdhM1";
    static final String CRED = "bf7f592233113e7a3a014be4de962b7179ddefcd70e4e0df5e9267d0082c9a2d";

    private static void body() {
        RegisterOp reg = new RegisterOp("6666", ADDR, "admin.qcc", 1793508092990L, CRED);
        UnregisterOp unreg = new UnregisterOp("6666", ADDR, "admin.qcc", 1793508192990L, 7L);

        // ── 1. 签名字符串向量 ──────────────────────────────────────
        ck(reg.toSign().equals("QNS1|register|6666|" + ADDR + "|admin.qcc|1793508092990|" + CRED),
                "register 签名字符串: " + reg.toSign());
        ck(unreg.toSign().equals("QNS1|unregister|6666|" + ADDR + "|admin.qcc|1793508192990|7"),
                "unregister 签名字符串: " + unreg.toSign());
        ck(reg.opHash().equals(Sha3.hashUtf8Hex(reg.toSign())), "opHash = SHA3-256(toSign)");
        ck(reg.label().equals("admin") && reg.tag().equals("qcc"), "label / tag 拆分");

        // ── 2. 二进制往返 ──────────────────────────────────────────
        NameOp r2 = NameOp.fromBytes(reg.toBytes());
        ck(r2 instanceof RegisterOp && r2.equals(reg) && r2.toSign().equals(reg.toSign()),
                "register 二进制往返后签名字符串不变");
        NameOp u2 = NameOp.fromBytes(unreg.toBytes());
        ck(u2 instanceof UnregisterOp && ((UnregisterOp) u2).regSeq == 7 && u2.equals(unreg),
                "unregister 二进制往返");
        ck(reg.toBytes().length < 160, "register 二进制 " + reg.toBytes().length + " 字节");

        // ── 3. 二进制畸形输入 ──────────────────────────────────────
        byte[] b = reg.toBytes();
        byte[] badMagic = b.clone(); badMagic[0] = 'X';
        ck(throwsIAE(() -> NameOp.fromBytes(badMagic)), "MAGIC 错误 → 拒绝");
        byte[] badType = b.clone(); badType[4] = 0x09;
        ck(throwsIAE(() -> NameOp.fromBytes(badType)), "未知类型 → 拒绝");
        byte[] trailing = java.util.Arrays.copyOf(b, b.length + 1);
        ck(throwsRuntime(() -> NameOp.fromBytes(trailing)), "尾部多余字节 → 拒绝");
        byte[] truncated = java.util.Arrays.copyOf(b, b.length - 1);
        ck(throwsRuntime(() -> NameOp.fromBytes(truncated)), "截断 → 拒绝");

        // ── 4. 结构校验 ────────────────────────────────────────────
        ck(throwsIAE(() -> new RegisterOp("6666", ADDR, "Admin.qcc", 1, CRED).toSign()), "大写 → 拒绝（客户端须先规范化）");
        ck(throwsIAE(() -> new RegisterOp("6666", ADDR, "admin", 1, CRED).toSign()), "缺 tag → 拒绝");
        ck(throwsIAE(() -> new RegisterOp("6666", ADDR, "a.b.qcc", 1, CRED).toSign()), "多级名称 → 拒绝");
        ck(throwsIAE(() -> new RegisterOp("6666", ADDR, ".qcc", 1, CRED).toSign()), "空 label → 拒绝");
        ck(throwsIAE(() -> new RegisterOp("6666", ADDR, "admin.", 1, CRED).toSign()), "空 tag → 拒绝");
        ck(throwsIAE(() -> new RegisterOp("6666", ADDR, "ad|min.qcc", 1, CRED).toSign()), "分隔符注入 → 拒绝");
        ck(throwsIAE(() -> new RegisterOp("6666", ADDR, "admín.qcc", 1, CRED).toSign()), "非 ASCII → 拒绝");
        ck(throwsIAE(() -> new RegisterOp("66|66", ADDR, "admin.qcc", 1, CRED).toSign()), "chain 注入 → 拒绝");
        ck(throwsIAE(() -> new RegisterOp("6666", "Q0Il" + ADDR.substring(4), "admin.qcc", 1, CRED).toSign()),
                "address 含非 Base58 字符 → 拒绝");
        ck(throwsIAE(() -> new RegisterOp("6666", ADDR, "admin.qcc", 0, CRED).toSign()), "timestamp=0 → 拒绝");
        ck(throwsIAE(() -> new RegisterOp("6666", ADDR, "admin.qcc", 1, CRED.toUpperCase()).toSign()),
                "credentialHash 大写 → 拒绝");
        ck(throwsIAE(() -> new RegisterOp("6666", ADDR, "admin.qcc", 1, CRED.substring(2)).toSign()),
                "credentialHash 长度错 → 拒绝");
        ck(throwsIAE(() -> new UnregisterOp("6666", ADDR, "admin.qcc", 1, 0).toSign()), "regSeq=0 → 拒绝");

        // ── 5. 字段变化必然改变签名字符串 ──────────────────────────
        ck(!new RegisterOp("9999", ADDR, "admin.qcc", 1793508092990L, CRED).toSign().equals(reg.toSign()),
                "chain 不同 → 签名字符串不同（防跨链重放）");
        ck(!new UnregisterOp("6666", ADDR, "admin.qcc", 1793508192990L, 8L).toSign().equals(unreg.toSign()),
                "regSeq 不同 → 签名字符串不同（旧删除签名失效）");
    }

    private static boolean throwsRuntime(Runnable r) {
        try { r.run(); return false; } catch (RuntimeException e) { return true; }
    }
}
