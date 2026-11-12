package qcc.name.config;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 本机公告地址判定（沿用 QCC LocalAddressResolver 的流程，IPv4 优先，IPv6 兜底），纯本地，不请求任何外部服务。
 *
 *   0. 配置 advertiseIp= 显式指定 → 直接采用（AWS / GCP / Azure 等 1:1 NAT 云主机必须指定）
 *   1. 网卡上直接持有公网 IPv4 → 采用，不再看 IPv6
 *   2. 否则取网卡上的全局 IPv6（2000::/3）
 *   3. 都没有 → NONE
 *
 * IPv6 取址规则（简化版，未依赖 QCC 的 Ipv6StableAddress）：
 *   优先 EUI-64 地址（接口标识中间为 ff:fe，由 MAC 派生，重启不变），其次按字符串排序取第一个。
 *   ⚠ Java 无法跨平台区分"隐私临时地址"与"稳定地址"；家用 IPv6 若开启了隐私扩展，
 *     地址会定期轮换 → 家用节点请在配置里写死 self，并在路由器上给本机固定后缀。
 */
public final class LocalAddressResolver {

    public enum Family { IPV4, IPV6, NONE }

    public record Resolved(Family family, String ip, String method, List<String> notes) {
        public boolean usable() { return family != Family.NONE && !ip.isEmpty(); }
    }

    private LocalAddressResolver() { }

    public static Resolved resolve(String advertiseIp) {
        List<String> notes = new ArrayList<>();
        if (advertiseIp != null && !advertiseIp.isBlank()) {
            String v = normalize(advertiseIp.trim());
            return new Resolved(v.contains(":") ? Family.IPV6 : Family.IPV4, v, "配置 advertiseIp 显式指定", notes);
        }
        List<String> v4 = publicIpv4();
        if (!v4.isEmpty()) {
            if (v4.size() > 1) notes.add("存在 " + v4.size() + " 个公网 IPv4 " + v4 + "，取第一个");
            return new Resolved(Family.IPV4, v4.getFirst(), "IPv4 网卡枚举", notes);
        }
        notes.add("网卡上没有公网 IPv4（处于 NAT 之后）；若是 1:1 NAT 云主机，请配置 advertiseIp=");
        List<String> v6 = globalIpv6(), eui = new ArrayList<>();
        for (String a : v6) if (isEui64(a)) eui.add(a);
        if (!eui.isEmpty()) return new Resolved(Family.IPV6, eui.getFirst(), "IPv6 网卡枚举（EUI-64 稳定地址）", notes);
        if (!v6.isEmpty()) {
            notes.add("⚠ 全局 IPv6 " + v6 + " 均非 EUI-64，可能是会轮换的隐私地址，建议路由器固定后缀并写死 self");
            return new Resolved(Family.IPV6, v6.getFirst(), "IPv6 网卡枚举", notes);
        }
        notes.add("网卡上也没有全局 IPv6");
        return new Resolved(Family.NONE, "", "全部失败", notes);
    }

    /** 网卡上直接绑定的公网 IPv4，排序保证每次重启选到同一个。 */
    public static List<String> publicIpv4() {
        List<String> out = new ArrayList<>();
        for (InetAddress a : interfaceAddresses())
            if (a instanceof Inet4Address v4 && !isPrivateOrReserved(v4.getAddress())) out.add(v4.getHostAddress());
        Collections.sort(out);
        return out;
    }

    /** 网卡上的全局单播 IPv6（2000::/3），去掉 scope 后缀并规范化。 */
    public static List<String> globalIpv6() {
        List<String> out = new ArrayList<>();
        for (InetAddress a : interfaceAddresses()) {
            if (!(a instanceof Inet6Address v6)) continue;
            byte[] b = v6.getAddress();
            if ((b[0] & 0xE0) != 0x20) continue;                          // 只要 2000::/3
            if ((b[0] & 0xFF) == 0x20 && (b[1] & 0xFF) == 0x01 && (b[2] & 0xFF) == 0x0d && (b[3] & 0xFF) == 0xb8) continue; // 2001:db8 文档段
            out.add(normalize(v6.getHostAddress()));
        }
        Collections.sort(out);
        return out;
    }

    /** RFC1918 私网 + 环回 + link-local + CGNAT + 保留段。 */
    public static boolean isPrivateOrReserved(byte[] b) {
        int o0 = b[0] & 0xFF, o1 = b[1] & 0xFF;
        if (o0 == 10) return true;
        if (o0 == 172 && o1 >= 16 && o1 <= 31) return true;
        if (o0 == 192 && o1 == 168) return true;
        if (o0 == 127) return true;
        if (o0 == 169 && o1 == 254) return true;
        if (o0 == 100 && (o1 & 0xC0) == 0x40) return true;              // CGNAT 100.64/10
        int o2 = b[2] & 0xFF;
        if (o0 == 192 && o1 == 0 && o2 == 2) return true;               // 文档段 192.0.2/24
        if (o0 == 198 && o1 == 51 && o2 == 100) return true;            // 文档段 198.51.100/24
        if (o0 == 203 && o1 == 0 && o2 == 113) return true;             // 文档段 203.0.113/24
        if (o0 == 198 && (o1 == 18 || o1 == 19)) return true;           // 基准测试 198.18/15
        return o0 == 0 || o0 >= 224;
    }

    /** 规范化：2001:0DB8::1 与 2001:db8:0:0:0:0:0:1 → 同一字符串；去掉 %scope 与方括号。 */
    public static String normalize(String ip) {
        String s = ip.startsWith("[") && ip.endsWith("]") ? ip.substring(1, ip.length() - 1) : ip;
        int pct = s.indexOf('%');
        if (pct >= 0) s = s.substring(0, pct);
        try {
            InetAddress a = InetAddress.getByName(s);       // 字面量 IP 不触发 DNS
            if (a instanceof Inet6Address) return compress6(a.getAddress());
            return a.getHostAddress();
        } catch (Exception e) {
            return s.toLowerCase();
        }
    }

    /** 两个配置值是否指同一地址（主机名会解析）。 */
    public static boolean sameHost(String a, String b) {
        try {
            for (InetAddress x : InetAddress.getAllByName(stripBrackets(a)))
                for (InetAddress y : InetAddress.getAllByName(stripBrackets(b)))
                    if (java.util.Arrays.equals(x.getAddress(), y.getAddress())) return true;
        } catch (Exception ignored) { }
        return normalize(a).equals(normalize(b));
    }

    // ── 内部 ──────────────────────────────────────────────────────

    static List<InetAddress> interfaceAddresses() {
        List<InetAddress> out = new ArrayList<>();
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback() || ni.isPointToPoint()) continue;
                out.addAll(Collections.list(ni.getInetAddresses()));
            }
        } catch (Exception e) {
            System.err.println("[addr] 网卡枚举失败: " + e.getMessage());
        }
        return out;
    }

    private static boolean isEui64(String v6) {
        try {
            byte[] b = InetAddress.getByName(v6).getAddress();
            return (b[11] & 0xFF) == 0xFF && (b[12] & 0xFF) == 0xFE;
        } catch (Exception e) {
            return false;
        }
    }

    /** RFC 5952 压缩形式：小写、去前导零、最长连续零段用 ::。 */
    private static String compress6(byte[] b) {
        int[] g = new int[8];
        for (int i = 0; i < 8; i++) g[i] = ((b[2 * i] & 0xFF) << 8) | (b[2 * i + 1] & 0xFF);
        int bestS = -1, bestL = 0;
        for (int i = 0; i < 8; ) {
            if (g[i] != 0) { i++; continue; }
            int j = i;
            while (j < 8 && g[j] == 0) j++;
            if (j - i > bestL && j - i >= 2) { bestS = i; bestL = j - i; }
            i = j;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i == bestS) { sb.append(i == 0 ? "::" : ":"); i += bestL - 1; continue; }
            sb.append(Integer.toHexString(g[i]));
            if (i < 7) sb.append(':');
        }
        return sb.toString();
    }

    private static String stripBrackets(String h) { return h.startsWith("[") && h.endsWith("]") ? h.substring(1, h.length() - 1) : h; }

    /** 手工核对：java -cp … qcc.name.config.LocalAddressResolver */
    public static void main(String[] a) {
        Resolved r = resolve(a.length > 0 ? a[0] : null);
        System.out.println("判定: " + r.family() + " · " + r.method() + " · 公告地址: \"" + r.ip() + "\"");
        for (String n : r.notes()) System.out.println("  " + n);
    }
}
