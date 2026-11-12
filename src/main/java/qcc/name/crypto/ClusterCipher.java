package qcc.name.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 节点间通讯加密：AES-256-GCM（JDK 自带，零依赖）。替代 HTTPS 与 IP 白名单：
 * 持有 clusterKey 即为集群成员（钱包托管完成后再叠加节点钱包签名）。
 *
 * ═══ 线格式 ═════════════════════════════════════════════════════
 *   MAGIC "QNSC"(4) | ver(1)=1 | ts u64 | nonce(12) | ciphertext + tag(16)
 *   AAD = MAGIC | ver | ts | nonce | utf8(path) | bind(12，响应才有)
 *
 *   - GCM 本身即认证加密，篡改任何一个字节（含 AAD）解密即失败，不需要另加 HMAC
 *   - path 进 AAD：一条 /internal/pull 的请求不能被拿去当 /internal/frame 用
 *   - 请求：|now - ts| ≤ 60s，且 nonce 在窗口内不得重复 → 防重放
 *   - 响应：AAD 绑定请求的 nonce → 不能用别的请求的响应冒充
 *   - 每条消息随机 12 字节 nonce；namespace 的消息量下 GCM nonce 碰撞概率可忽略
 */
public final class ClusterCipher {

    static final byte[] MAGIC = "QNSC".getBytes(StandardCharsets.US_ASCII);
    static final byte VER = 1;
    static final int NONCE = 12, TAG_BITS = 128, HEADER = 4 + 1 + 8 + NONCE;
    public static final long MAX_SKEW_MS = 60_000;

    private final SecretKeySpec key;
    private final SecureRandom rnd = new SecureRandom();
    private final Map<String, Long> seen = new ConcurrentHashMap<>();   // 请求 nonce → 到期时间

    /** 一条已解密的请求：明文 + 它的 nonce（用于绑定响应）。 */
    public record Opened(byte[] plain, byte[] nonce) {}

    public ClusterCipher(byte[] key32) {
        if (key32 == null || key32.length != 32) throw new IllegalArgumentException("clusterKey 必须 32 字节");
        this.key = new SecretKeySpec(key32.clone(), "AES");
    }

    // ── 请求 ──────────────────────────────────────────────────────

    /** 加密请求，返回 {密文, 本次 nonce}。 */
    public byte[][] sealRequest(String path, byte[] plain) {
        byte[] n = new byte[NONCE];
        rnd.nextBytes(n);
        return new byte[][]{seal(path, plain, n, null), n};
    }

    /** 解密请求：校验时间窗与重放。失败抛 SecurityException。 */
    public Opened openRequest(String path, byte[] wire) {
        ByteBuffer b = header(wire);
        long ts = b.getLong();
        byte[] n = new byte[NONCE];
        b.get(n);
        long now = System.currentTimeMillis();
        if (Math.abs(now - ts) > MAX_SKEW_MS) throw new SecurityException("时间戳超出 ±60s（检查节点时钟/NTP）");
        byte[] plain = decrypt(path, wire, ts, n, null);
        String id = Base64Url.of(n);
        if (seen.putIfAbsent(id, now + 2 * MAX_SKEW_MS) != null) throw new SecurityException("重放的请求");
        if (seen.size() > 50_000) purge(now);
        return new Opened(plain, n);
    }

    // ── 响应 ──────────────────────────────────────────────────────

    public byte[] sealResponse(String path, byte[] plain, byte[] requestNonce) {
        byte[] n = new byte[NONCE];
        rnd.nextBytes(n);
        return seal(path + "#resp", plain, n, requestNonce);
    }

    public byte[] openResponse(String path, byte[] wire, byte[] requestNonce) {
        ByteBuffer b = header(wire);
        long ts = b.getLong();
        byte[] n = new byte[NONCE];
        b.get(n);
        return decrypt(path + "#resp", wire, ts, n, requestNonce);
    }

    // ── 实现 ──────────────────────────────────────────────────────

    private byte[] seal(String path, byte[] plain, byte[] n, byte[] bind) {
        long ts = System.currentTimeMillis();
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, n));
            c.updateAAD(aad(ts, n, path, bind));
            byte[] ct = c.doFinal(plain);
            ByteBuffer out = ByteBuffer.allocate(HEADER + ct.length);
            out.put(MAGIC).put(VER).putLong(ts).put(n).put(ct);
            return out.array();
        } catch (Exception e) {
            throw new IllegalStateException("加密失败", e);
        }
    }

    private byte[] decrypt(String path, byte[] wire, long ts, byte[] n, byte[] bind) {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, n));
            c.updateAAD(aad(ts, n, path, bind));
            return c.doFinal(wire, HEADER, wire.length - HEADER);
        } catch (Exception e) {
            throw new SecurityException("解密/认证失败（clusterKey 不一致或数据被篡改）");
        }
    }

    private static ByteBuffer header(byte[] wire) {
        if (wire == null || wire.length < HEADER + 16) throw new SecurityException("密文过短");
        ByteBuffer b = ByteBuffer.wrap(wire);
        byte[] m = new byte[4];
        b.get(m);
        if (!Arrays.equals(m, MAGIC)) throw new SecurityException("MAGIC 错误");
        if (b.get() != VER) throw new SecurityException("版本不支持");
        return b;
    }

    private static byte[] aad(long ts, byte[] n, String path, byte[] bind) {
        byte[] p = path.getBytes(StandardCharsets.UTF_8);
        ByteBuffer b = ByteBuffer.allocate(4 + 1 + 8 + NONCE + p.length + (bind == null ? 0 : bind.length));
        b.put(MAGIC).put(VER).putLong(ts).put(n).put(p);
        if (bind != null) b.put(bind);
        return b.array();
    }

    private void purge(long now) {
        for (Iterator<Map.Entry<String, Long>> it = seen.entrySet().iterator(); it.hasNext(); )
            if (it.next().getValue() < now) it.remove();
    }

    private static final class Base64Url {
        static String of(byte[] b) { return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(b); }
    }
}
