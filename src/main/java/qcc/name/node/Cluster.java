package qcc.name.node;

import qcc.name.http.Json;
import qcc.name.protocol.StrictJson;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.*;

/**
 * 集群成员表（P2P 发现的结果），持久化在 数据目录/cluster.json。
 *
 *   term / primary   当前任期与主节点。主节点不轮换，只在故障时由选举或手动 promote 更换
 *   cores            核心节点，按加入顺序（创世节点第一个）：参与写入确认、投票、接班
 *   observers        冗余节点：只同步与查询
 *   addrs            各节点最新的 IP:端口 —— 软状态，随心跳更新（IPv6 地址轮换不影响，nodeId 不变即可）
 *   ver              成员表版本：主节点每次修改 +1；成员按 (term, ver) 采纳更新的表
 *   votedTerm/For    本节点投过的票（防止同一任期投两次）
 *
 * 成员表由主节点维护并广播；其他节点只采纳，不自行修改（选举成功的新主除外）。
 */
public final class Cluster {

    public record Addr(String host, int port) {
        public String url() { return "http://" + (host.contains(":") ? "[" + host + "]" : host) + ":" + port; }
        @Override public String toString() { return (host.contains(":") ? "[" + host + "]" : host) + ":" + port; }
    }

    public int term;
    public String primary;                       // null = 尚未加入集群
    public long ver;
    public final List<String> cores = new ArrayList<>();
    public final List<String> observers = new ArrayList<>();
    public final Map<String, Addr> addrs = new LinkedHashMap<>();
    public int votedTerm;
    public String votedFor = "";

    private final Path file;

    Cluster(Path file) { this.file = file; }

    // ── 查询 ──────────────────────────────────────────────────────

    public boolean joined()            { return primary != null; }
    public boolean isCore(String id)   { return cores.contains(id); }
    public boolean isMember(String id) { return cores.contains(id) || observers.contains(id); }
    /** 过半数核心节点（含自己）。 */
    public int majority()              { return cores.size() / 2 + 1; }

    public List<String> members() { List<String> l = new ArrayList<>(cores); l.addAll(observers); return l; }

    public Map<String, String> urls() {
        Map<String, String> m = new LinkedHashMap<>();
        for (var e : addrs.entrySet()) m.put(e.getKey(), e.getValue().url());
        return m;
    }

    /** 本节点在主节点之后的接班顺位（1 = 紧接主节点）；不是核心节点返回 -1。 */
    public int rankAfterPrimary(String id) {
        int pi = cores.indexOf(primary), me = cores.indexOf(id);
        if (pi < 0 || me < 0 || me == pi) return -1;
        return Math.floorMod(me - pi, cores.size());
    }

    // ── 序列化 ────────────────────────────────────────────────────

    public synchronized Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("term", term);
        m.put("primary", primary == null ? "" : primary);
        m.put("ver", ver);
        m.put("cores", new ArrayList<>(cores));
        m.put("observers", new ArrayList<>(observers));
        Map<String, Object> a = new LinkedHashMap<>();
        for (var e : addrs.entrySet()) a.put(e.getKey(), e.getValue().toString());
        m.put("addrs", a);
        return m;
    }

    /** 采纳别处的成员表（仅表内容，不含投票记录）。 */
    public synchronized void load(Map<String, Object> m) {
        term = (int) StrictJson.num(m, "term");
        String p = StrictJson.strAllowEmpty(m, "primary");
        primary = p.isEmpty() ? null : p;
        ver = StrictJson.num(m, "ver");
        cores.clear();
        cores.addAll(StrictJson.strArr(m, "cores"));
        observers.clear();
        observers.addAll(StrictJson.strArr(m, "observers"));
        addrs.clear();
        for (var e : StrictJson.obj(m, "addrs").entrySet()) addrs.put(e.getKey(), parseAddr((String) e.getValue()));
    }

    /** 对方的表是否比本地新：term 更高，或 term 相同而版本更高。 */
    public synchronized boolean olderThan(Map<String, Object> m) {
        long t = StrictJson.num(m, "term"), v = StrictJson.num(m, "ver");
        return t > term || (t == term && v > ver);
    }

    public static Addr parseAddr(String hp) {
        hp = hp.trim();
        if (hp.startsWith("[")) {
            int c = hp.indexOf(']');
            if (c < 0) throw new IllegalArgumentException("IPv6 应写成 [地址]:端口：" + hp);
            String h = hp.substring(1, c);
            return new Addr(h, c + 1 < hp.length() && hp.charAt(c + 1) == ':' ? Integer.parseInt(hp.substring(c + 2)) : 9180);
        }
        int c = hp.lastIndexOf(':');
        if (c > 0 && hp.indexOf(':') == c) return new Addr(hp.substring(0, c), Integer.parseInt(hp.substring(c + 1)));
        if (c > 0) return new Addr(hp, 9180);                     // 裸 IPv6，无端口
        return new Addr(hp, 9180);
    }

    // ── 持久化 ────────────────────────────────────────────────────

    public synchronized boolean loadFile() {
        if (!Files.isRegularFile(file)) return false;
        try {
            Map<String, Object> m = StrictJson.parseObject(Files.readAllBytes(file));
            load(m);
            votedTerm = (int) StrictJson.num(m, "votedTerm");
            votedFor = StrictJson.strAllowEmpty(m, "votedFor");
            return true;
        } catch (Exception e) {
            throw new IllegalStateException("cluster.json 损坏：" + file + "（" + e.getMessage() + "）", e);
        }
    }

    public synchronized void save() {
        Map<String, Object> m = toMap();
        m.put("votedTerm", votedTerm);
        m.put("votedFor", votedFor);
        try {
            Files.createDirectories(file.getParent());
            Path tmp = file.resolveSibling("cluster.json.tmp");
            Files.write(tmp, Json.write(m).getBytes(StandardCharsets.UTF_8));
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new IllegalStateException("cluster.json 写入失败", e);
        }
    }

    public synchronized void delete() {
        try { Files.deleteIfExists(file); } catch (IOException ignored) { }
    }

    @Override
    public synchronized String toString() {
        return "term=" + term + " 主=" + shortId(primary) + " 核心" + cores.size() + " 冗余" + observers.size() + " ver=" + ver;
    }

    static String shortId(String id) { return id == null ? "（未加入）" : id.length() > 10 ? id.substring(0, 10) + "…" : id; }
}
