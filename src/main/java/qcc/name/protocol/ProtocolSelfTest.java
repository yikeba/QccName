package qcc.name.protocol;

import qcc.name.Check;
import qcc.name.codec.Sha3;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** 引导协议加载与边界规则。需在工程根目录运行（读取 qcc-*.json 与 testdata/）。 */
public final class ProtocolSelfTest {

    public static int run(String[] args) throws Exception {
        Check c = new Check();
        byte[] raw  = Files.readAllBytes(Path.of("qcc-name-v1.0.0.json"));
        byte[] meta = Files.readAllBytes(Path.of("qcc-meta-v1.0.0.json"));
        String s = new String(raw, StandardCharsets.UTF_8);

        c.ck(Sha3.toHex(Sha3.hash(meta)).equals(NameProtocol.META_HASH), "本地 qcc-meta 文件 hash == 链上 META_HASH");
        byte[] onChain = ProtocolLoader.payloadFromTxResponse(Files.readAllBytes(Path.of("testdata/meta-tx-response.json")));
        c.ck(java.util.Arrays.equals(onChain, meta), "链上 /v1/hash 响应还原（有符号字节 & 0xFF）与原文件逐字节一致");

        NameProtocol p = ProtocolLoader.load(raw, null);
        c.ck(p.tags.containsKey("qcc") && p.pledgeTag.equals("qccio") && p.cooldownMs == 2592000000L, "qcc-name 协议加载: " + p);
        c.ck(c.throwsAny(() -> ProtocolLoader.load(raw, "00".repeat(32))), "hash 不符 → 拒绝启动");

        c.ck(c.throwsAny(() -> NameProtocol.parse(bytes(s.replace("\"status\": \"voluntary\",", "\"status\": \"voluntary\",\n  \"extra\": 1,")))),
                "未知顶层字段 → 拒绝启动");
        c.ck(c.throwsAny(() -> NameProtocol.parse(bytes(s.replace("\"minBackupAcks\": 1", "\"minBackupAcks\": 1, \"newParam\": 2")))),
                "params 未知字段 → 拒绝启动");
        c.ck(c.throwsAny(() -> NameProtocol.parse(bytes(s.replace("{params.pledgeTag}", "{params.noSuch}")))),
                "docs 引用无法解析 → 拒绝启动");
        c.ck(c.throwsAny(() -> NameProtocol.parse(bytes(s.replace("\"spec\": \"a2", "\"spec\": \"b2")))),
                "spec 不是 qcc-meta/1 → 拒绝启动");
        c.ck(c.throwsAny(() -> NameProtocol.parse(bytes(s.replace("\"tsMonotonic\", \"tagOpen\"", "\"tsMonotonic\", \"noSuchCheck\"")))),
                "未实现的检查项 → 拒绝启动");
        c.ck(c.throwsAny(() -> NameProtocol.parse(bytes(s.replace("\"44\": \"pledgeStillValid\"", "\"45\": \"x\"")))),
                "实现会产出的结果码在协议中缺失 → 拒绝启动");
        c.ck(c.throwsAny(() -> NameProtocol.parse(bytes(s.replace("\"level\": \"L1\"", "\"level\": \"L3\"")))),
                "声明了做不到的可验证等级 → 拒绝启动");
        c.ck(c.throwsAny(() -> NameProtocol.parse(bytes(s.replace("\n", "\r\n")))), "CRLF → 拒绝启动");
        c.ck(c.throwsAny(() -> NameProtocol.parse(bytes(s.replaceFirst("\"minAmount\": 1000000000", "\"minAmount\": 1.5")))),
                "浮点 → 拒绝启动");
        return c.failed();
    }

    private static byte[] bytes(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    public static void main(String[] args) throws Exception { if (run(args) != 0) System.exit(1); }
}
