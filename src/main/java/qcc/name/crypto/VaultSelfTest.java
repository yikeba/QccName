package qcc.name.crypto;

import qcc.name.Check;
import qcc.name.codec.Sha3;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

/**
 * 节点私钥管理器自测：钱包格式导入、地址 / 配对校验、封存与还原、换机器解不开、碎片缺失、导入文件删除。
 */
public final class VaultSelfTest {

    public static int run(String[] a) throws Exception {
        Check c = new Check();
        // 固定测试密钥（独立实现 dilithium-py 生成的 FIPS 204 标准编码，与钱包 privateKeyHex 同格式），两种后端都能用
        List<String> kl = Files.readAllLines(Path.of("testdata/vault-test-key.txt")).stream()
                .filter(l -> !l.isBlank() && !l.startsWith("#")).toList();
        MlDsa87.Keys k = new MlDsa87.Keys(Sha3.fromHex(kl.get(0).strip()), Sha3.fromHex(kl.get(1).strip()));
        String addr = QccAddress.derive(k.pub());
        c.ck(k.priv().length == NodeKeyVault.PRIV_LEN && k.pub().length == MlDsa87.PUBKEY_LEN, "测试密钥：私钥 4896 / 公钥 2592 字节");
        byte[] m0 = "cross-check".getBytes(StandardCharsets.UTF_8);
        c.ck(MlDsa87.verify(k.pub(), m0, MlDsa87.signRaw(k.priv(), m0)), "钱包格式私钥签名、公钥验签（" + MlDsa87.source() + "）");

        Path root = Files.createTempDirectory("qccname-vault");
        Path imp = root.resolve(NodeKeyVault.IMPORT_FILE);
        Path vault = root.resolve("vault").resolve(addr);
        NodeKeyVault.MachineId.override = "machine-A".getBytes(StandardCharsets.UTF_8);

        // ── 钱包导出片段（无外层花括号、带 index、尾逗号）──
        String frag = "\"index\":2,\n\"address\":\"" + addr + "\",\n\"publicKeyHex\":\"" + Sha3.toHex(k.pub())
                + "\",\n\"privateKeyHex\":\"" + Sha3.toHex(k.priv()) + "\",\n";
        Files.writeString(imp, frag);

        // nodeId 不一致 → 拒绝，文件保留
        c.ck(throwsIse(() -> NodeKeyVault.open(imp, vault, "qccname-test", "QWasmDyBQzCTdUhj6NLyfAzU6z5sTSdhM1")),
                "address 与配置的 nodeId 不一致 → 拒绝启动");
        c.ck(Files.exists(imp), "校验失败时导入文件保留不动");

        // 公钥换成别人的 → 拒绝
        MlDsa87.Keys other = MlDsa87.generate();
        Files.writeString(imp, frag.replace(Sha3.toHex(k.pub()), Sha3.toHex(other.pub())));
        c.ck(throwsIse(() -> NodeKeyVault.open(imp, vault, "qccname-test", addr)), "公钥推导地址 ≠ address → 拒绝");

        // 私钥换成别的（同长度，改掉中间一段）→ 拒绝（配对校验）
        byte[] wrong = k.priv().clone();
        for (int i = 200; i < 260; i++) wrong[i] ^= 0x5a;
        Files.writeString(imp, frag.replace(Sha3.toHex(k.priv()), Sha3.toHex(wrong)));
        c.ck(throwsIse(() -> NodeKeyVault.open(imp, vault, "qccname-test", addr)), "私钥与公钥不是一对 → 拒绝");

        // 正确导入
        Files.writeString(imp, frag);
        NodeKeyVault v = NodeKeyVault.open(imp, vault, "qccname-test", addr);
        c.ck(v != null && "导入并封存".equals(v.origin()), "钱包片段导入成功");
        c.ck(!Files.exists(imp), "导入后 nodekey.json 已覆写并删除");
        List<Path> shards = list(vault);
        c.ck(shards.size() == 5, "封存为 5 个随机文件名的碎片（1 片元数据 + 4 片密文）：" + shards.size());
        String privHex = Sha3.toHex(k.priv());
        boolean leak = false;
        for (Path p : shards) {
            String h = Sha3.toHex(Files.readAllBytes(p));
            if (h.contains(privHex.substring(0, 64)) || h.contains(Sha3.toHex(k.pub()).substring(0, 64))) leak = true;
        }
        c.ck(!leak, "碎片文件中搜不到私钥 / 公钥的明文片段");

        byte[] msg = ("QNN1|proof|6666|" + addr + "|" + "ab".repeat(32) + "|1|").getBytes(StandardCharsets.UTF_8);
        c.ck(MlDsa87.verify(k.pub(), msg, v.sign(msg)), "管理器签名可用原公钥验签");

        // 重启：从封存还原
        NodeKeyVault v2 = NodeKeyVault.open(imp, vault, "qccname-test", addr);
        c.ck(v2 != null && "从封存还原".equals(v2.origin()), "重启后从封存还原");
        c.ck(MlDsa87.verify(k.pub(), msg, v2.sign(msg)), "还原后的私钥签名有效");

        // 拷到另一台机器 → 解不开
        NodeKeyVault.MachineId.override = "machine-B".getBytes(StandardCharsets.UTF_8);
        c.ck(throwsIse(() -> NodeKeyVault.open(imp, vault, "qccname-test", addr)), "换机器（本机标识不同）→ 无法解封");
        NodeKeyVault.MachineId.override = "machine-A".getBytes(StandardCharsets.UTF_8);

        // instance 不同 → 解不开（同机另一个实例拿不到）
        c.ck(throwsIse(() -> NodeKeyVault.open(imp, vault, "qccname-other", addr)), "instance 不同 → 无法解封");

        // 缺一片 → 拒绝
        Path gone = list(vault).get(0);
        byte[] keep = Files.readAllBytes(gone);
        Files.delete(gone);
        c.ck(throwsIse(() -> NodeKeyVault.open(imp, vault, "qccname-test", addr)), "缺一片碎片 → 拒绝（提示重新导入）");
        Files.write(gone, keep);
        c.ck(NodeKeyVault.open(imp, vault, "qccname-test", addr) != null, "碎片补回后恢复正常");

        // 篡改一片 → 拒绝
        Path t = list(vault).get(1);
        byte[] bad = Files.readAllBytes(t);
        bad[bad.length - 1] ^= 1;
        Files.write(t, bad);
        c.ck(throwsIse(() -> NodeKeyVault.open(imp, vault, "qccname-test", addr)), "碎片被改动 → 拒绝");

        // 重新导入覆盖旧封存
        Files.writeString(imp, frag);
        c.ck(NodeKeyVault.open(imp, vault, "qccname-test", addr) != null && list(vault).size() == 5,
                "重新导入：新封存替换旧碎片");

        // 都没有 → null
        Path empty = root.resolve("vault-empty");
        c.ck(NodeKeyVault.open(root.resolve("none.json"), empty, "qccname-test", addr) == null, "没有导入文件也没有封存 → 返回 null");

        NodeKeyVault.MachineId.override = null;
        return c.failed();
    }

    private static List<Path> list(Path dir) throws Exception {
        try (Stream<Path> s = Files.list(dir)) { return s.filter(p -> p.toString().endsWith(".bin")).sorted().toList(); }
    }

    interface Io { Object run() throws Exception; }

    private static boolean throwsIse(Io r) {
        try { r.run(); return false; } catch (IllegalStateException e) { return true; } catch (Exception e) { return false; }
    }

    public static void main(String[] a) throws Exception { if (run(a) != 0) System.exit(1); }
}
