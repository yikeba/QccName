package qcc.name.node;

import qcc.name.chain.MultiChainView;
import qcc.name.config.QccNameConfig;
import qcc.name.config.LocalAddressResolver;
import qcc.name.crypto.ClusterCipher;
import qcc.name.crypto.MlDsa87;
import qcc.name.crypto.NodeKeyVault;
import qcc.name.http.HttpTransport;
import qcc.name.http.NameHttpServer;
import qcc.name.http.TlsContext;
import qcc.name.protocol.NameProtocol;
import qcc.name.protocol.ProtocolLoader;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * 节点启动入口。无启动参数，配置只来自应用当前目录的 ./qccname.properties，
 * 必填 nodeId / clusterKey / type（genesis / production / backup），非创世节点再填 seeds。数据在 ~/qccname/ 下。
 * 节点间通讯 AES-256-GCM（clusterKey）；对外接口明文 HTTP。
 * 日志同时写到 home/logs/qccname-yyyyMMdd.log。
 */
public final class NodeMain {

    public static void main(String[] args) throws Exception {
        QccNameConfig c;
        try {
            c = QccNameConfig.load();
        } catch (IllegalStateException e) {
            System.err.println("配置错误：" + e.getMessage());
            System.exit(2);
            return;
        }
        try {
            start(c);
        } catch (IllegalStateException e) {
            System.err.println("启动失败：" + e.getMessage());
            System.exit(2);
        }
    }

    public static NameNode start(QccNameConfig c) throws Exception {
        String id = c.requireNodeId();
        QccNameConfig.Type type = c.requireType();
        ClusterCipher cipher = new ClusterCipher(c.requireClusterKey());
        teeLog(c.logDir());

        NameProtocol p = ProtocolLoader.loadFile(c.protocolFile, c.protocolHash);

        // 节点私钥：nodekey.json 导入并封存（随后删除），或从本机封存还原
        NodeKeyVault nodeKey = NodeKeyVault.open(c.nodeKeyFile, c.vaultDir(), c.instanceId, id);
        if (nodeKey == null && type.core())
            throw new IllegalStateException("缺少节点私钥：把钱包导出的 " + id + " 那一段（address / publicKeyHex / privateKeyHex）存成 "
                    + c.nodeKeyFile.toAbsolutePath() + " 后重新启动（导入后自动封存并删除该文件）");

        LocalAddressResolver.Resolved addr0 = c.resolveAddress();
        boolean core = type.core();
        Supplier<Cluster.Addr> selfAddr = new Supplier<>() {          // 60 秒重新判定一次（IPv6 地址轮换）
            LocalAddressResolver.Resolved cur = addr0;
            long at = System.currentTimeMillis();
            @Override public synchronized Cluster.Addr get() {
                if (System.currentTimeMillis() - at > 60_000) { cur = c.resolveAddress(); at = System.currentTimeMillis(); }
                return cur.usable() ? new Cluster.Addr(cur.ip(), c.port) : null;
            }
        };

        NameNode.logOps = c.logOps;
        MultiChainView chain = new MultiChainView(c.chains);
        if (c.protocolTx != null) p = ProtocolLoader.withPublisherFromChain(p, chain, c.protocolTx);
        else if (p.hasReservedOnlyTags())
            throw new IllegalStateException("协议中有 registration=reserved 的 tag（企业级 namespace），必须配置 protocolTx 启用 Reserved，否则没有任何名字可用");
        Path dir = c.nodeDir();
        HttpTransport net = new HttpTransport(Map.of(), cipher);
        boolean fresh = !Files.exists(dir.resolve("cluster.json"));
        if (type == QccNameConfig.Type.GENESIS && fresh && !c.seeds.isEmpty()) {
            // 创世前确认 seeds 上没有正在运行的集群（防止清空数据后误以创世身份另起一个集群）
            for (String u : c.seeds)
                if (net.clusterAt(u, "{\"t\":\"ping\"}".getBytes(StandardCharsets.UTF_8)) != null)
                    throw new IllegalStateException("type=genesis，但 seeds 中的 " + u + " 已有集群在运行 —— 本机应改为 type=production 加入，而不是另起一个集群");
        }
        List<String> seeds = type == QccNameConfig.Type.GENESIS ? List.of() : c.seeds;
        NameNode node = new NameNode(NodeConfig.p2p(id, dir, p, c.instanceId, chain, net, seeds, selfAddr, core));

        node.probe();                                              // 开放端口前确认本地成员表没有过期
        Set<InetAddress> nodeIps = ConcurrentHashMap.newKeySet();   // 限流豁免：成员 IP（节点间鉴权靠 clusterKey）
        String bind = c.bind;
        com.sun.net.httpserver.HttpServer hs;
        try {
            hs = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress(bind, c.port), 256);
        } catch (java.net.SocketException e) {
            if (!bind.equals("::")) throw e;
            System.out.println("  ⚠ 本机不支持 IPv6 监听（" + e.getMessage() + "），改为 0.0.0.0（仅 IPv4）");
            bind = "0.0.0.0";
            hs = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress(bind, c.port), 256);
        }
        NameHttpServer http = new NameHttpServer(node, chain, hs, nodeIps, cipher, c.webDir);
        http.setNodeKey(nodeKey, c.nodesTx);
        http.start();

        // HTTPS（可选）：keystore 文件存在才启用；与 HTTP 提供相同的接口与静态网站
        NameHttpServer https = null;
        com.sun.net.httpserver.HttpsServer hss = null;
        TlsContext tls = null;
        String httpsInfo;
        if (c.httpsPort > 0 && Files.isRegularFile(c.keystore)) {
            try {
                tls = new TlsContext(c.keystore, c.keystorePass);
                hss = com.sun.net.httpserver.HttpsServer.create(new InetSocketAddress(bind, c.httpsPort), 256);
                hss.setHttpsConfigurator(new com.sun.net.httpserver.HttpsConfigurator(tls.load()));
                https = new NameHttpServer(node, chain, hss, nodeIps, cipher, c.webDir);
                https.setNodeKey(nodeKey, c.nodesTx);
                https.start();
                httpsInfo = "HTTPS " + c.httpsPort + "（证书 " + c.keystore + "，自动热加载）";
            } catch (java.net.BindException e) {
                httpsInfo = "HTTPS 跳过：端口 " + c.httpsPort + " 已被占用（可能是同机的另一个实例），本实例只提供 HTTP " + c.port;
                tls = null; https = null;
                if (hss != null) try { hss.stop(0); } catch (Exception ignore) { }
            } catch (Exception e) {
                httpsInfo = "HTTPS 跳过：" + e.getMessage() + "（检查 keystore / keystorePass / 端口权限），本实例只提供 HTTP " + c.port;
                tls = null; https = null;
                if (hss != null) try { hss.stop(0); } catch (Exception ignore) { }
            }
        } else {
            httpsInfo = c.httpsPort <= 0 ? "HTTPS 未启用（httpsPort=0）" : "HTTPS 未启用（未找到证书 " + c.keystore + "）";
        }

        System.out.println("qccname 节点已启动 " + id + "  端口 " + c.port + "  类型=" + type.label + "（" + (core ? "核心" : "冗余") + "）");
        System.out.println("  配置 " + c);
        System.out.println("  公告地址 " + (addr0.usable() ? addr0.ip() : "（无：只能主动连出，其他节点推送不到本机）")
                + "  [" + addr0.family() + " · " + addr0.method() + "]");
        for (String n : addr0.notes()) System.out.println("    " + n);
        if (!c.advertiseIp.isEmpty() && !onLocalNic(c.advertiseIp))
            System.out.println("    ⚠ advertiseIp=" + c.advertiseIp + " 不在本机网卡上：其他节点将按这个地址连接本机。"
                    + "只有 1:1 NAT 云主机 / 端口转发时才应如此，否则请改成本机真实 IP");
        if (type == QccNameConfig.Type.PRODUCTION && addr0.usable()
                && (addr0.family() != LocalAddressResolver.Family.IPV4 || isPrivateV4(addr0.ip())))
            System.out.println("    ⚠ 生产节点应使用公网 IPv4（当前 " + addr0.ip() + "）；局域网测试可忽略，IPv6 节点请用 type=backup");
        if (node.joined() && node.isCore() != core)
            System.out.println("  ⚠ 配置 type=" + type.name().toLowerCase() + "，但本机在集群中已登记为" + (node.isCore() ? "核心" : "冗余")
                    + "：角色以首次加入为准；要更换类型，请先在主节点 /admin/remove 本机并清空本机数据目录后重新加入");
        if (type == QccNameConfig.Type.GENESIS && node.isPrimary() && node.cores().size() == 1)
            System.out.println("  ★ 本机为创世节点（type=genesis）。整个集群只能有一台这样配置，其他节点用 production / backup 并把 seeds 指向已运行的节点");
        System.out.println("  链节点 " + chain.describe());
        System.out.println("  协议 " + p + (c.protocolHash == null ? "  （⚠ 未校验 hash，公网前请配置 protocolHash）" : ""));
        System.out.println("  保留名 " + (p.reservedEnabled()
                ? "启用，发布者 " + p.reservedPublisher + "，交易列表 " + c.reservedFile.toAbsolutePath() + "（每 30 秒检查）"
                : "关闭（未配置 protocolTx）：所有 tag 完全开放，先到先得"));
        System.out.println("  签名 " + MlDsa87.source() + "  通讯 AES-256-GCM  数据 " + dir + "  已有 " + node.maxSeq() + " 帧");
        System.out.println("  节点私钥 " + (nodeKey == null
                ? "无（type=backup，不提供 /v1/node/proof）"
                : nodeKey.origin() + "，封存 " + c.vaultDir() + "（绑定本机）  /v1/node/proof 已启用"
                + (c.nodesTx == null ? "（⚠ 未配置 nodesTx）" : "  nodesTx " + c.nodesTx.substring(0, 16) + "…")));
        System.out.println("  网站 " + (Files.isDirectory(c.webDir) ? c.webDir + "（替换文件即生效）" : "目录 " + c.webDir + " 不存在（创建并放入 index.html 即可访问，无需重启）")
                + "  " + httpsInfo);
        System.out.println("  日志 " + c.logDir().toAbsolutePath().resolve("qccname-" + LocalDate.now().format(DateTimeFormatter.BASIC_ISO_DATE) + ".log")
                + "  逐帧日志 " + (c.logOps ? "开（[写入] / [同步]）" : "关（logOps=false）") + "  每 60 秒 [进度] 汇总");
        if (c.chains.size() < 2) System.out.println("  ⚠ 只配置了 1 个链节点：链节点故障时不可写，且质押回收需要 ≥2 个链节点确认");

        if (!node.joined()) node.join();
        System.out.println("  集群 " + node.clusterInfo() + (node.isPrimary() ? "  ← 本机为主" : ""));
        if (node.joined() && !node.isPrimary()) node.syncTick();

        ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "qccname-sync");
            t.setDaemon(true);
            return t;
        });
        timer.scheduleWithFixedDelay(() -> {
            try {
                node.syncTick();
                refreshIps(node, nodeIps);
            } catch (Throwable e) {
                System.err.println("[sync] " + e);
            }
        }, 10, 10, TimeUnit.SECONDS);
        if (tls != null) {
            TlsContext t = tls;
            timer.scheduleWithFixedDelay(() -> {
                if (t.reloadIfChanged()) System.out.println("[https] 证书已更新并重新加载");
            }, 10, 10, TimeUnit.MINUTES);
        }
        ReservedWatcher reservedWatcher = new ReservedWatcher(node, chain, c.reservedFile);
        timer.scheduleWithFixedDelay(() -> {
            try { reservedWatcher.tick(); } catch (Throwable e) { System.err.println("[保留名] " + e); }
        }, 5, 30, TimeUnit.SECONDS);
        timer.scheduleWithFixedDelay(() -> {
            try { System.out.println(node.progressLine()); } catch (Throwable e) { System.err.println("[进度] " + e); }
        }, 60, 60, TimeUnit.SECONDS);

        NameHttpServer srv = http, srvs = https;
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            timer.shutdownNow();
            srv.stop();
            if (srvs != null) srvs.stop();
            node.close();
            System.out.println("qccname 节点已停止");
        }));
        return node;
    }

    private static boolean isPrivateV4(String ip) {
        try { return LocalAddressResolver.isPrivateOrReserved(InetAddress.getByName(ip).getAddress()); }
        catch (Exception e) { return false; }
    }

    private static boolean onLocalNic(String ip) {
        String want = LocalAddressResolver.normalize(ip);
        try {
            for (java.net.NetworkInterface ni : java.util.Collections.list(java.net.NetworkInterface.getNetworkInterfaces()))
                for (InetAddress a : java.util.Collections.list(ni.getInetAddresses()))
                    if (LocalAddressResolver.normalize(a.getHostAddress()).equals(want)) return true;
        } catch (Exception ignored) { }
        return false;
    }

    @SuppressWarnings("unchecked")
    private static void refreshIps(NameNode node, Set<InetAddress> ips) {
        Object a = node.clusterTable().get("addrs");
        if (!(a instanceof Map<?, ?> m)) return;
        Set<InetAddress> now = new HashSet<>();
        for (Object v : m.values()) {
            try { now.addAll(Arrays.asList(InetAddress.getAllByName(Cluster.parseAddr((String) v).host()))); } catch (Exception ignored) { }
        }
        ips.retainAll(now);
        ips.addAll(now);
    }

    // ── 日志：控制台 + 按天文件 ───────────────────────────────────

    private static void teeLog(Path logDir) {
        try {
            Files.createDirectories(logDir);
            OutputStream file = new DailyFile(logDir);
            System.setOut(new PrintStream(new Tee(System.out, file, false), true, StandardCharsets.UTF_8));
            System.setErr(new PrintStream(new Tee(System.err, file, true), true, StandardCharsets.UTF_8));
        } catch (Exception e) {
            System.err.println("日志文件不可写（只输出到控制台）：" + e);
        }
    }

    /** 每行加时间戳写入文件；控制台原样输出。 */
    private static final class Tee extends OutputStream {
        private final OutputStream console, file;
        private final boolean err;
        private boolean lineStart = true;
        private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS ");

        Tee(OutputStream console, OutputStream file, boolean err) { this.console = console; this.file = file; this.err = err; }

        @Override public void write(int b) throws java.io.IOException { write(new byte[]{(byte) b}, 0, 1); }

        @Override public void write(byte[] b, int off, int len) throws java.io.IOException {
            console.write(b, off, len);
            synchronized (file) {
                int start = off;
                for (int i = off; i < off + len; i++) {
                    if (lineStart) {
                        file.write((LocalDateTime.now().format(TS) + (err ? "E " : "  ")).getBytes(StandardCharsets.UTF_8));
                        lineStart = false;
                    }
                    if (b[i] == '\n') {
                        file.write(b, start, i - start + 1);
                        start = i + 1;
                        lineStart = true;
                    }
                }
                if (start < off + len) file.write(b, start, off + len - start);
            }
        }

        @Override public void flush() throws java.io.IOException { console.flush(); synchronized (file) { file.flush(); } }
    }

    /** 按日期切换的日志文件 qccname-yyyyMMdd.log。 */
    private static final class DailyFile extends OutputStream {
        private final Path dir;
        private LocalDate day;
        private OutputStream out;

        DailyFile(Path dir) { this.dir = dir; }

        private OutputStream cur() throws java.io.IOException {
            LocalDate d = LocalDate.now();
            if (!d.equals(day)) {
                if (out != null) out.close();
                out = new FileOutputStream(dir.resolve("qccname-" + d.format(DateTimeFormatter.BASIC_ISO_DATE) + ".log").toFile(), true);
                day = d;
            }
            return out;
        }

        @Override public synchronized void write(int b) throws java.io.IOException { cur().write(b); }
        @Override public synchronized void write(byte[] b, int off, int len) throws java.io.IOException { cur().write(b, off, len); }
        @Override public synchronized void flush() throws java.io.IOException { if (out != null) out.flush(); }
    }
}