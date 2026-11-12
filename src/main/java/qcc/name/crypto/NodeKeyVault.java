package qcc.name.crypto;

import qcc.name.codec.Sha3;
import qcc.name.protocol.StrictJson;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;

/**
 * 节点私钥管理器（nodeId 对应的 0 资产钱包私钥）。
 *
 * ═══ 导入（只做一次）════════════════════════════════════════════
 *   把钱包导出的那一段原样存成应用目录下的 nodekey.json（外层花括号可有可无，index 字段忽略）：
 *     {"index":2,"address":"Q…","publicKeyHex":"…","privateKeyHex":"…"}
 *   启动时检查：address = 配置的 nodeId；公钥推导出的地址 = address；私钥签名、公钥验签通过。
 *   任何一项不通过：拒绝启动，nodekey.json 原样保留。
 *   全部通过：封存（见下），然后覆写并删除 nodekey.json。
 *
 * ═══ 封存（绑定本机 + 碎片化）═════════════════════════════════════
 *   K   = HKDF-SHA3-256(ikm = 本机标识, salt = 随机 32 字节, info = "QNV1|instance|nodeId")
 *   本机标识：Linux /etc/machine-id；Windows 注册表 MachineGuid；macOS IOPlatformUUID
 *   密文 = AES-256-GCM(K, iv 随机 12 字节, aad = "QNV1|nodeId", 私钥 4896 ‖ 公钥 2592)
 *   密文切成 SHARDS 片，每片用独立的随机掩码异或，写进 vaultDir 下随机文件名的 .bin 文件；
 *   盐和 iv 单独一片。文件拷到别的机器上解不开，只拷走部分碎片也还原不了。
 *
 * ═══ 内存 ═════════════════════════════════════════════════════════
 *   私钥只以"异或随机掩码"的形式常驻，每次签名临时还原，签完立即清零。
 *
 * ═══ 边界 ═════════════════════════════════════════════════════════
 *   这是提高门槛，不是绝对安全：拿到本机 root 并愿意反编译 jar / 转储内存的攻击者仍能取得私钥。
 *   止损靠 0 资产钱包 + 链上发布新版 qcc-name-nodes 删掉这个 nodeId。
 *   重装系统（本机标识改变）后封存失效，节点提示重新放入 nodekey.json。
 *   SSD / 日志型文件系统上覆写不保证物理擦除；导入文件请勿经过网盘、聊天或版本库。
 */
public final class NodeKeyVault {

    public static final int PRIV_LEN = MlDsa87.PRIVKEY_LEN;   // FIPS 204 ML-DSA-87 私钥标准编码 4896 字节
    public static final String IMPORT_FILE = "nodekey.json";
    private static final int SHARDS = 4;
    private static final byte[] MAGIC = "QNV1".getBytes(StandardCharsets.US_ASCII);
    private static final byte KIND_META = 0, KIND_DATA = 1;

    private final String nodeId;
    private final byte[] pub;
    private final byte[] maskedPriv;
    private final byte[] pad;
    private final String origin;
    private static final SecureRandom RND = new SecureRandom();

    private NodeKeyVault(String nodeId, byte[] pub, byte[] priv, String origin) {
        this.nodeId = nodeId;
        this.pub = pub.clone();
        this.pad = new byte[priv.length];
        RND.nextBytes(pad);
        this.maskedPriv = new byte[priv.length];
        for (int i = 0; i < priv.length; i++) maskedPriv[i] = (byte) (priv[i] ^ pad[i]);
        Arrays.fill(priv, (byte) 0);
        this.origin = origin;
    }

    public String nodeId()     { return nodeId; }
    public byte[] publicKey()  { return pub.clone(); }
    public String publicKeyHex() { return Sha3.toHex(pub); }
    /** "导入并封存" 或 "从封存还原"。 */
    public String origin()     { return origin; }

    /** 用节点私钥签名（ML-DSA-87 纯模式、空 context）。消息请使用 UTF-8 文本（与 QCC 验签器一致）。 */
    public byte[] sign(byte[] message) {
        byte[] priv = new byte[maskedPriv.length];
        try {
            synchronized (this) {
                for (int i = 0; i < priv.length; i++) priv[i] = (byte) (maskedPriv[i] ^ pad[i]);
            }
            return MlDsa87.signRaw(priv, message);
        } finally {
            Arrays.fill(priv, (byte) 0);
        }
    }

    // ═══ 打开：导入 / 还原 ═════════════════════════════════════════

    /**
     * @param importFile 导入文件（通常为应用目录下的 nodekey.json）
     * @param vaultDir   封存目录（与帧日志分开，rejoin 清空数据时不受影响）
     * @return 私钥管理器；既没有导入文件也没有封存时返回 null
     */
    public static NodeKeyVault open(Path importFile, Path vaultDir, String instance, String nodeId) throws IOException {
        MlDsa87.selfCheck();
        if (Files.isRegularFile(importFile)) {
            NodeKeyVault v = importAndSeal(importFile, vaultDir, instance, nodeId);
            wipe(importFile);
            return v;
        }
        if (hasShards(vaultDir)) return unseal(vaultDir, instance, nodeId);
        return null;
    }

    private static NodeKeyVault importAndSeal(Path f, Path vaultDir, String instance, String nodeId) throws IOException {
        String text = Files.readString(f, StandardCharsets.UTF_8).strip();
        while (text.endsWith(",")) text = text.substring(0, text.length() - 1).strip();
        if (!text.startsWith("{")) text = "{" + text + "}";
        Map<String, Object> j;
        try {
            j = StrictJson.parseObject(text.getBytes(StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            throw new IllegalStateException(f + " 不是合法的钱包导出格式（需要 address / publicKeyHex / privateKeyHex）：" + e.getMessage());
        }
        String address = StrictJson.str(j, "address").strip();
        byte[] pub  = hex(StrictJson.str(j, "publicKeyHex"), "publicKeyHex");
        byte[] priv = hex(StrictJson.str(j, "privateKeyHex"), "privateKeyHex");
        try {
            if (!address.equals(nodeId))
                throw new IllegalStateException(f + " 的 address=" + address + " 与配置的 nodeId=" + nodeId + " 不一致");
            if (pub.length != MlDsa87.PUBKEY_LEN)
                throw new IllegalStateException("publicKeyHex 长度 " + pub.length + " 字节，ML-DSA-87 应为 " + MlDsa87.PUBKEY_LEN);
            if (priv.length != PRIV_LEN)
                throw new IllegalStateException("privateKeyHex 长度 " + priv.length + " 字节，ML-DSA-87 应为 " + PRIV_LEN);
            if (!QccAddress.matches(pub, address))
                throw new IllegalStateException("公钥推导出的地址是 " + QccAddress.derive(pub) + "，不是 " + address);
            if (!pairMatches(priv, pub))
                throw new IllegalStateException("私钥与公钥不是一对（测试签名验签失败）");
            seal(vaultDir, instance, nodeId, priv, pub);
            NodeKeyVault back = unseal(vaultDir, instance, nodeId);     // 立即读回，确认封存可用后才删导入文件
            if (!Arrays.equals(back.pub, pub)) throw new IllegalStateException("封存读回校验失败");
            return new NodeKeyVault(nodeId, pub, priv, "导入并封存");
        } finally {
            Arrays.fill(priv, (byte) 0);
        }
    }

    private static boolean pairMatches(byte[] priv, byte[] pub) {
        byte[] r = new byte[16];
        RND.nextBytes(r);
        byte[] msg = ("qccname-vault-selftest|" + Sha3.toHex(r)).getBytes(StandardCharsets.UTF_8);
        try {
            return MlDsa87.verify(pub, msg, MlDsa87.signRaw(priv.clone(), msg));
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ═══ 封存 / 还原 ═══════════════════════════════════════════════

    static void seal(Path dir, String instance, String nodeId, byte[] priv, byte[] pub) throws IOException {
        Files.createDirectories(dir);
        restrict(dir, true);
        byte[] salt = random(32), iv = random(12);
        byte[] key = deriveKey(salt, instance, nodeId);
        byte[] plain = new byte[priv.length + pub.length];
        byte[] ct;
        try {
            System.arraycopy(priv, 0, plain, 0, priv.length);
            System.arraycopy(pub, 0, plain, priv.length, pub.length);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            c.updateAAD(aad(nodeId));
            ct = c.doFinal(plain);
        } catch (Exception e) {
            throw new IllegalStateException("封存加密失败", e);
        } finally {
            Arrays.fill(plain, (byte) 0);
            Arrays.fill(key, (byte) 0);
        }
        // 先写新碎片，再删旧碎片（中途失败时旧封存仍可用）
        java.util.List<Path> old = listShards(dir);
        byte[] tag = Sha3.hash(nodeId.getBytes(StandardCharsets.UTF_8));
        ByteBuffer meta = ByteBuffer.allocate(32 + 12 + 4);
        meta.put(salt).put(iv).putInt(ct.length);
        writeShard(dir, tag, KIND_META, 0, meta.array());
        int per = (ct.length + SHARDS - 1) / SHARDS;
        for (int i = 0; i < SHARDS; i++) {
            int from = Math.min(ct.length, i * per), to = Math.min(ct.length, from + per);
            writeShard(dir, tag, KIND_DATA, i, Arrays.copyOfRange(ct, from, to));
        }
        for (Path p : old) wipe(p);
    }

    static NodeKeyVault unseal(Path dir, String instance, String nodeId) throws IOException {
        byte[] tag = Sha3.hash(nodeId.getBytes(StandardCharsets.UTF_8));
        byte[] meta = null;
        TreeMap<Integer, byte[]> parts = new TreeMap<>();
        for (Path p : listShards(dir)) {
            Shard s = readShard(p);
            if (s == null || !Arrays.equals(s.tag, tag)) continue;
            if (s.kind == KIND_META) meta = s.data;
            else parts.put(s.index, s.data);
        }
        if (meta == null || parts.size() != SHARDS)
            throw new IllegalStateException("节点私钥封存不完整（" + dir + "，nodeId=" + nodeId + "）：请重新放入 " + IMPORT_FILE);
        ByteBuffer mb = ByteBuffer.wrap(meta);
        byte[] salt = new byte[32], iv = new byte[12];
        mb.get(salt).get(iv);
        int len = mb.getInt();
        ByteArrayOutputStream ct = new ByteArrayOutputStream();
        for (byte[] d : parts.values()) ct.write(d);
        if (ct.size() != len) throw new IllegalStateException("节点私钥封存长度不符：请重新放入 " + IMPORT_FILE);
        byte[] key = deriveKey(salt, instance, nodeId);
        byte[] plain;
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            c.updateAAD(aad(nodeId));
            plain = c.doFinal(ct.toByteArray());
        } catch (javax.crypto.AEADBadTagException e) {
            throw new IllegalStateException("节点私钥封存无法解开：本机标识已改变（重装系统 / 换机器）或文件被改动。请重新放入 " + IMPORT_FILE);
        } catch (Exception e) {
            throw new IllegalStateException("节点私钥解封失败", e);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
        try {
            if (plain.length != PRIV_LEN + MlDsa87.PUBKEY_LEN) throw new IllegalStateException("封存内容长度不符");
            byte[] priv = Arrays.copyOf(plain, PRIV_LEN);
            byte[] pub = Arrays.copyOfRange(plain, PRIV_LEN, plain.length);
            if (!QccAddress.matches(pub, nodeId)) throw new IllegalStateException("封存的公钥与 nodeId 不符：请重新放入 " + IMPORT_FILE);
            return new NodeKeyVault(nodeId, pub, priv, "从封存还原");
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    // ── 碎片文件：MAGIC(4) | tag(32) | kind(1) | index(1) | len(4) | mask(32) | data XOR stream(mask) ──

    private record Shard(byte[] tag, byte kind, int index, byte[] data) {}

    private static void writeShard(Path dir, byte[] tag, byte kind, int index, byte[] data) throws IOException {
        byte[] mask = random(32);
        byte[] masked = xorStream(data, mask);
        ByteBuffer b = ByteBuffer.allocate(4 + 32 + 1 + 1 + 4 + 32 + masked.length);
        b.put(MAGIC).put(tag).put(kind).put((byte) index).putInt(masked.length).put(mask).put(masked);
        Path f;
        do { f = dir.resolve(Sha3.toHex(random(8)) + ".bin"); } while (Files.exists(f));
        Files.write(f, b.array(), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, StandardOpenOption.SYNC);
        restrict(f, false);
    }

    private static Shard readShard(Path f) {
        try {
            byte[] all = Files.readAllBytes(f);
            ByteBuffer b = ByteBuffer.wrap(all);
            byte[] m = new byte[4];
            b.get(m);
            if (!Arrays.equals(m, MAGIC)) return null;
            byte[] tag = new byte[32];
            b.get(tag);
            byte kind = b.get();
            int index = b.get() & 0xff;
            int len = b.getInt();
            byte[] mask = new byte[32];
            b.get(mask);
            if (len != b.remaining()) return null;
            byte[] masked = new byte[len];
            b.get(masked);
            return new Shard(tag, kind, index, xorStream(masked, mask));
        } catch (Exception e) {
            return null;
        }
    }

    /** 掩码流：SHA3-256(mask ‖ u32(counter)) 依次拼接。 */
    private static byte[] xorStream(byte[] in, byte[] mask) {
        byte[] out = new byte[in.length];
        int ctr = 0;
        for (int off = 0; off < in.length; off += 32, ctr++) {
            byte[] ks = Sha3.hash(mask, ByteBuffer.allocate(4).putInt(ctr).array());
            for (int i = 0; i < 32 && off + i < in.length; i++) out[off + i] = (byte) (in[off + i] ^ ks[i]);
        }
        return out;
    }

    private static java.util.List<Path> listShards(Path dir) throws IOException {
        java.util.List<Path> out = new java.util.ArrayList<>();
        if (!Files.isDirectory(dir)) return out;
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, "*.bin")) {
            for (Path p : ds) out.add(p);
        }
        return out;
    }

    private static boolean hasShards(Path dir) throws IOException { return !listShards(dir).isEmpty(); }

    // ── 密钥派生：HKDF-SHA3-256（RFC 5869）──────────────────────────

    private static byte[] deriveKey(byte[] salt, String instance, String nodeId) {
        byte[] ikm = MachineId.read();
        try {
            byte[] prk = hmac(salt, ikm);
            byte[] info = ("QNV1|" + instance + "|" + nodeId).getBytes(StandardCharsets.UTF_8);
            byte[] t1 = hmac(prk, concat(info, new byte[]{1}));
            Arrays.fill(prk, (byte) 0);
            return t1;                                                // 32 字节 = AES-256
        } finally {
            Arrays.fill(ikm, (byte) 0);
        }
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac m = Mac.getInstance("HmacSHA3-256");
            m.init(new SecretKeySpec(key, "HmacSHA3-256"));
            return m.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA3-256 不可用", e);
        }
    }

    private static byte[] aad(String nodeId) { return ("QNV1|" + nodeId).getBytes(StandardCharsets.UTF_8); }

    // ── 工具 ────────────────────────────────────────────────────

    private static byte[] hex(String s, String field) {
        String h = s.strip().toLowerCase();
        if (h.startsWith("0x")) h = h.substring(2);
        if (h.isEmpty() || (h.length() & 1) != 0 || !h.matches("[0-9a-f]+"))
            throw new IllegalStateException(field + " 不是 hex 字符串");
        return Sha3.fromHex(h);
    }

    private static byte[] random(int n) { byte[] b = new byte[n]; RND.nextBytes(b); return b; }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] o = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, o, a.length, b.length);
        return o;
    }

    /** 覆写后删除。 */
    static void wipe(Path f) {
        try {
            long n = Files.size(f);
            try (RandomAccessFile raf = new RandomAccessFile(f.toFile(), "rw")) {
                byte[] buf = new byte[8192];
                for (long off = 0; off < n; off += buf.length) {
                    RND.nextBytes(buf);
                    raf.write(buf, 0, (int) Math.min(buf.length, n - off));
                }
                raf.getFD().sync();
            }
        } catch (IOException ignored) { }
        try { Files.deleteIfExists(f); } catch (IOException e) {
            System.err.println("⚠ 无法删除 " + f + "，请手工删除：" + e.getMessage());
        }
    }

    /** 尽量只允许本用户访问（POSIX 文件系统；Windows 上忽略）。 */
    private static void restrict(Path p, boolean dir) {
        try {
            Files.setPosixFilePermissions(p, PosixFilePermissions.fromString(dir ? "rwx------" : "rw-------"));
        } catch (UnsupportedOperationException | IOException ignored) { }
    }

    // ═══ 本机标识 ═══════════════════════════════════════════════════

    /** 读取操作系统的机器标识（重装系统才会改变）。取不到时拒绝封存，不退回到可拷贝的文件。 */
    static final class MachineId {
        /** 测试用：非空时直接使用。 */
        static volatile byte[] override;

        static byte[] read() {
            if (override != null) return override.clone();
            String os = System.getProperty("os.name", "").toLowerCase();
            String id = null;
            try {
                if (os.contains("win")) {
                    id = grep(run("reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"), "MachineGuid");
                } else if (os.contains("mac")) {
                    id = grep(run("ioreg", "-rd1", "-c", "IOPlatformExpertDevice"), "IOPlatformUUID");
                } else {
                    for (String f : new String[]{"/etc/machine-id", "/var/lib/dbus/machine-id"}) {
                        Path p = Path.of(f);
                        if (Files.isRegularFile(p)) { id = Files.readString(p).strip(); if (!id.isEmpty()) break; }
                    }
                }
            } catch (Exception ignored) { }
            if (id == null || id.isBlank())
                throw new IllegalStateException("读取不到本机标识（Linux /etc/machine-id、Windows MachineGuid、macOS IOPlatformUUID），无法封存节点私钥");
            return ("qccname-machine|" + id.strip()).getBytes(StandardCharsets.UTF_8);
        }

        private static String run(String... cmd) throws Exception {
            Process pr = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            byte[] out = pr.getInputStream().readAllBytes();
            pr.waitFor(10, TimeUnit.SECONDS);
            return new String(out, StandardCharsets.UTF_8);
        }

        /** 取包含 key 的那一行的最后一个值（reg: "MachineGuid REG_SZ xxx"；ioreg: "\"IOPlatformUUID\" = \"xxx\""）。 */
        private static String grep(String text, String key) {
            for (String line : text.split("\\R")) {
                if (!line.contains(key)) continue;
                String v = line.substring(line.indexOf(key) + key.length()).replace("\"", "").replace("=", " ").strip();
                String[] parts = v.split("\\s+");
                return parts[parts.length - 1];
            }
            return null;
        }
    }
}
