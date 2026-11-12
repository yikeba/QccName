package qcc.name.codec;

import java.util.*;

/**
 * codec 层一致性向量 —— 第一批。
 *
 * 这些断言不是普通单元测试,它们定义了"什么叫兼容实现"。
 * 任何第二实现(Dart 验证器、未来的 Rust 重放器)必须全部通过,
 * 才能声称兼容 qcc-canonical-binary/1。规范文字总有歧义,向量没有。
 *
 * 运行:java -Dstdout.encoding=UTF-8 -cp &lt;out&gt; qcc.name.codec.CodecSelfTest
 */
public class CodecSelfTest {

    private static int failed = 0;

    private static void ck(boolean cond, String msg) {
        if (!cond) failed++;
        System.out.println((cond ? "  OK   " : "  FAIL ") + msg);
    }

    public static void main(String[] args) {

        // ── 1. SHA3-256 实现正确性(NIST 标准向量)──────────────────
        ck(Sha3.hashUtf8Hex("abc").equals(
                "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
                "SHA3-256(\"abc\") 符合 NIST 向量");
        ck(Sha3.hashUtf8Hex("").equals(
                "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
                "SHA3-256(\"\") 符合 NIST 向量");

        // ── 2. 多段哈希等价于拼接 ──────────────────────────────────
        ck(Arrays.equals(Sha3.hash(new byte[]{1, 2, 3}, new byte[]{4, 5}),
                         Sha3.hash(new byte[]{1, 2, 3, 4, 5})),
                "多段哈希等价于拼接后哈希");

        // ── 3. hex 严格性:绝不静默容错 ────────────────────────────
        ck(throwsOn(() -> Sha3.fromHex("0g")),   "非法 hex 字符抛异常");
        ck(throwsOn(() -> Sha3.fromHex("abc")),  "奇数长度 hex 抛异常");
        ck(throwsOn(() -> Sha3.fromHex32("00")), "短 hex 抛异常,不补零");

        // ── 4. null 与空串必须编码不同 ─────────────────────────────
        // 否则 {owner:null} 与 {owner:""} 哈希相同,状态可被伪造成另一个状态
        ck(!Arrays.equals(new QccCanonicalWriter().str(null).toBytes(),
                          new QccCanonicalWriter().str("").toBytes()),
                "null 与空串编码不同");

        // ── 5. map 编码与插入顺序无关 ──────────────────────────────
        // 这是"禁止依赖哈希容器迭代顺序"那条纪律的可执行形式
        Map<String, byte[]> m1 = new HashMap<>();
        m1.put("zebra", new byte[]{1});
        m1.put("alpha", new byte[]{2});
        m1.put("mid",   new byte[]{3});
        Map<String, byte[]> m2 = new LinkedHashMap<>();
        m2.put("alpha", new byte[]{2});
        m2.put("mid",   new byte[]{3});
        m2.put("zebra", new byte[]{1});
        ck(Arrays.equals(new QccCanonicalWriter().sortedMap(m1).toBytes(),
                         new QccCanonicalWriter().sortedMap(m2).toBytes()),
                "map 编码与插入顺序无关");

        // ── 6. UTF-8 字节序 != Java 的 UTF-16 码元序 ───────────────
        // 全角 A (U+FF21) 与 🔐 (U+1F510):两种排序结果相反
        String wideA = "\uFF21", lock = "\uD83D\uDD10";
        boolean utf16Order = wideA.compareTo(lock) < 0;
        boolean utf8Order  = QccCanonicalWriter.compareUtf8(wideA, lock) < 0;
        ck(utf16Order != utf8Order,
                "UTF-8 字节序确实不同于 UTF-16 码元序(所以必须显式按字节比较)");

        // ── 7. 完整往返 ────────────────────────────────────────────
        String h64 = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        QccCanonicalWriter w = new QccCanonicalWriter();
        w.u8(7).bool(true).u32(4294967295L).u64(Long.MAX_VALUE)
         .str("中文🔐").str(null).hash32Hex(h64)
         .strList(List.of("a", "b")).sortedMap(m1);

        QccCanonicalReader r = new QccCanonicalReader(w.toBytes());
        ck(r.u8() == 7 && r.bool() && r.u32() == 4294967295L && r.u64() == Long.MAX_VALUE,
                "定长字段往返");
        ck("中文🔐".equals(r.str()) && r.str() == null, "UTF-8 与 null 往返");
        ck(h64.equals(r.hash32Hex()), "hash32 往返");
        ck(List.of("a", "b").equals(r.strList()), "strList 往返");
        ck(r.sortedMap().size() == 3, "sortedMap 往返");
        ck(!throwsOn(r::finish), "字节被完全消费");

        // ── 8. 防御性:构造的巨大长度前缀不能 OOM ───────────────────
        ck(throwsOn(() -> new QccCanonicalReader(new byte[]{0x40, 0, 0, 0}).bytes()),
                "巨大长度前缀被拦截(不会 new byte[1GB])");
        ck(throwsOn(() -> new QccCanonicalReader(new byte[]{0, 0, 0, 8, 1, 2}).bytes()),
                "声明长度超过剩余字节被拦截");

        // ── 9. 乱序 map 必须被发现 ─────────────────────────────────
        // 同一个逻辑 map 只能有一种合法编码,否则 execHash 失去意义
        QccCanonicalWriter bad = new QccCanonicalWriter();
        bad.u32(2);
        bad.str("zebra"); bad.bytes(new byte[]{1});
        bad.str("alpha"); bad.bytes(new byte[]{2});
        ck(throwsOn(() -> new QccCanonicalReader(bad.toBytes()).sortedMap()),
                "key 未按字节序升序的 map 被拒绝");

        // ── 10. u64 拒绝负值(协议 intOverflow=reject)───────────────
        ck(throwsOn(() -> new QccCanonicalWriter().u64(-1)), "u64 写入负值被拒绝");

        // ── 11. 尾部多余字节视为格式错误 ───────────────────────────
        QccCanonicalReader r2 = new QccCanonicalReader(
                new QccCanonicalWriter().u8(1).u8(2).toBytes());
        r2.u8();
        ck(throwsOn(r2::finish), "尾部残留字节被拒绝");

        System.out.println();
        System.out.println(failed == 0 ? "全部通过" : (failed + " 项失败"));
        if (failed != 0) System.exit(1);
    }

    private static boolean throwsOn(Runnable r) {
        try { r.run(); return false; } catch (Exception e) { return true; }
    }
}
