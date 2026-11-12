package qcc.name.config;

import qcc.name.node.Cluster;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.*;

/**
 * 节点配置（P2P）。只读应用当前目录下的 ./qccname.properties（IDE 中即工程根目录，可直接编辑）；
 * 不存在时在当前目录生成模板（含新生成的 clusterKey）并退出。
 * 一台服务器可以跑多个实例（每个实例一个进程、一个应用目录、一份 qccname.properties），数据按实例切开：
 *   ~/qccname/{instance}/{nodeId}/   帧日志、签名库、cluster.json（生产数据）
 *   ~/qccname/{instance}/logs/       运行日志、pid
 * 同机实例共用（只读）：
 *   ~/qccname/ssl/                   HTTPS 证书（keystore 可配置）；443 被同机另一实例占用时自动跳过 HTTPS
 *   ~/qccname/web/                   静态网站（webDir 可配置）
 *   ~/qccname/dev/                   DevClient 的开发密钥
 * ═══ 必填 ═══════════════════════════════════════════════════════
 *   nodeId      本机 QCC 地址（明文；钱包托管完成后改为节点钱包签名）。配置文件优先，否则用 DEFAULT_NODE_ID
 *   clusterKey  节点间 AES-256-GCM 密钥（64 位 hex），所有节点相同；只放在配置文件里，切勿提交到代码仓库
 *   type        genesis 创世（第一台，核心）/ production 生产（核心：确认、投票、接班，用公网 IPv4）
 *               / backup 备份（冗余：只同步与查询，用于 IPv6 / 家庭节点）
 *   seeds       已在运行的任意节点 IP:端口，逗号分隔，能连上一个即可。production / backup 必填；genesis 留空
 * ═══ 可选 ═══════════════════════════════════════════════════════
 *   port        本机端口，默认 9180
 *   advertiseIp 本机公告 IP。空 = 自动判定（网卡上的公网 IPv4 优先，否则全局 IPv6）；局域网测试、1:1 NAT 云主机须填
 *   chains      QCC 公链 API 列表，默认 DEFAULT_CHAINS
 *   protocol / protocolHash / instance / bind
 *   home        本实例数据目录，默认 ~/qccname/{instance}
 *   protocolTx  本协议在 QCC 公链上的交易 hash。配置后：启动时取回该交易，核对 payload = 本地协议，
 *               交易 from 即保留名发布者，Reserved 启用；不配置 = Reserved 关闭，所有 tag 完全开放。
 *               所有节点必须相同（参与 genesisExecHash，不同会立即分叉报警）
 *   reserved    Reserved 交易 hash 列表文件，默认 ./Reserved.config（每行一个交易 hash，按发布顺序追加，# 注释）。
 *               每 30 秒检查一次；主节点取回新交易并写入日志，其他节点从日志同步
 *   nodeKey     节点私钥导入文件，默认 ./nodekey.json（钱包导出的 address / publicKeyHex / privateKeyHex）。
 *               首次启动校验后封存到 {home}/vault/{nodeId}/（绑定本机、碎片化），随后覆写并删除导入文件。
 *               genesis / production 必须有节点私钥；backup 可以没有（不对客户端提供节点证明）
 *   nodesTx     本实例 qcc-name-nodes 最新一版的交易 hash（写入 /v1/node/proof 的签名内容）；空 = 未发布
 *   webDir      静态网站目录，默认 ~/qccname/web（HTTP 与 HTTPS 端口都提供；直接替换文件即生效）
 *   httpsPort / keystore / keystorePass
 *               HTTPS：keystore 文件存在才启用（默认 ~/qccname/ssl/qccname.jks，也支持 .p12），端口默认 443；
 *               证书文件更新后自动热加载（每 10 分钟检查），无需重启
 */
public final class QccNameConfig {

    /** 代码默认 nodeId（方便本地测试）。配置文件写了 nodeId= 时以配置文件为准。开源仓库里保持为空。 */
    public static final String DEFAULT_NODE_ID = "";

    public static final int DEFAULT_PORT = 9180;

    private static final String USER_HOME = System.getProperty("user.home");
    /** 全部数据（生产数据、日志、开发密钥）的根目录。 */
    public static final Path ROOT_DIR = Path.of(USER_HOME, "qccname");
    /** 配置文件：应用当前目录。 */
    public static final Path CONFIG_FILE = Path.of("qccname.properties");

    /** 节点类型。 */
    public enum Type {
        GENESIS("创世"), PRODUCTION("生产"), BACKUP("备份");
        public final String label;
        Type(String l) { label = l; }
        public boolean core() { return this != BACKUP; }
    }

    /**
     * 默认 QCC 公链 API。⚠ 端口 9080 按测试链 45.92.158.123:9080 推定，其余节点请核对；
     * IPv6 节点只有本机支持 IPv6 时可用，IPv4 主机上会被自动跳过。
     */
    public static final List<String> DEFAULT_CHAINS = List.of(
            "http://45.92.158.123:9080",
            "http://192.131.142.226:9080",
            "http://104.128.190.31:9080",
            "http://23.238.114.155:9080",
            "http://104.223.85.211:9080",
            "http://[2001:f40:978:1c58:2f1:f5ff:fe35:fd73]:9080");

    public final String       nodeId;         // 客户端等非节点进程可能为 null
    public final String       nodeIdSource;
    public final byte[]       clusterKey;     // null = 未配置（客户端不需要）
    public final List<String> seeds;          // 节点 URL
    public final int          port;
    public final String       advertiseIp;    // 配置值，可空
    public final Type         type;           // 客户端进程可为 null
    public final List<String> chains;
    public final Path         protocolFile;
    public final String       protocolHash;
    public final String       protocolTx;     // null = Reserved 关闭
    public final Path         reservedFile;
    public final String       instanceId;
    public final Path         home;
    public final String       bind;
    public final boolean      logOps;         // 每帧打印一行 [写入] / [同步]
    public final Path         webDir;         // 静态网站目录（Flutter Web / HTML），改网页无需重启
    public final int          httpsPort;      // 0 = 不启用 HTTPS
    public final Path         keystore;       // .jks 或 .p12；文件存在才启用 HTTPS
    public final String       keystorePass;
    public final Path         devKeys;
    public final Path         nodeKeyFile;    // 节点私钥导入文件（导入后被删除）
    public final String       nodesTx;        // null = 未发布 qcc-name-nodes
    public final Path         source;

    private QccNameConfig(Properties p, Path source) {
        this.source = source;
        String id = p.getProperty("nodeId", "").trim();
        if (!id.isEmpty())                     { nodeId = id;                    nodeIdSource = "配置文件"; }
        else if (!DEFAULT_NODE_ID.isBlank())   { nodeId = DEFAULT_NODE_ID.trim(); nodeIdSource = "代码默认 DEFAULT_NODE_ID"; }
        else                                   { nodeId = null;                  nodeIdSource = "未配置"; }
        if (nodeId != null) checkAddress(nodeId);
        String key = p.getProperty("clusterKey", "").trim();
        this.clusterKey = key.isEmpty() ? null : parseKey(key);
        this.port = Integer.parseInt(p.getProperty("port", String.valueOf(DEFAULT_PORT)).trim());
        QccNamePort.assertNotQccPort(port, "port");
        List<String> sd = new ArrayList<>();
        for (String s : p.getProperty("seeds", "").split(","))
            if (!s.isBlank()) sd.add(Cluster.parseAddr(s.trim()).url());
        this.seeds = List.copyOf(sd);
        this.advertiseIp = p.getProperty("advertiseIp", "").trim();
        String t = p.getProperty("type", "").trim().toLowerCase();
        this.type = switch (t) {
            case "" -> null;
            case "genesis" -> Type.GENESIS;
            case "production" -> Type.PRODUCTION;
            case "backup" -> Type.BACKUP;
            default -> throw new IllegalStateException("type 只能是 genesis / production / backup：" + t);
        };
        List<String> cs = new ArrayList<>();
        for (String u : p.getProperty("chains", "").split(",")) if (!u.isBlank()) cs.add(trimSlash(u.trim()));
        this.chains = cs.isEmpty() ? DEFAULT_CHAINS : List.copyOf(cs);
        this.protocolFile = Path.of(p.getProperty("protocol", "qcc-name-public-v1.0.0.json").trim());
        this.protocolHash = blankToNull(p.getProperty("protocolHash"));
        this.protocolTx   = blankToNull(p.getProperty("protocolTx"));
        if (protocolTx != null && !protocolTx.matches("[0-9a-f]{64}"))
            throw new IllegalStateException("protocolTx 必须是 64 位小写 hex：" + protocolTx);
        this.reservedFile = Path.of(p.getProperty("reserved", "Reserved.config").trim());
        this.instanceId   = p.getProperty("instance", "qccname-test").trim();
        if (!instanceId.matches("[A-Za-z0-9._-]{1,64}") || instanceId.startsWith("."))
            throw new IllegalStateException("instance 只允许字母、数字、. _ -（同时用作数据目录名）：" + instanceId);
        String h = p.getProperty("home", "").trim();
        this.home         = h.isEmpty() ? ROOT_DIR.resolve(instanceId) : Path.of(h);
        this.bind         = p.getProperty("bind", "::").trim();
        this.logOps       = Boolean.parseBoolean(p.getProperty("logOps", "true").trim());
        this.webDir       = Path.of(p.getProperty("webDir", ROOT_DIR.resolve("web").toString()).trim());
        this.httpsPort    = Integer.parseInt(p.getProperty("httpsPort", "443").trim());
        this.keystore     = Path.of(p.getProperty("keystore", ROOT_DIR.resolve("ssl").resolve("qccname.jks").toString()).trim());
        this.keystorePass = p.getProperty("keystorePass", "").trim();
        this.devKeys      = ROOT_DIR.resolve("dev");
        this.nodeKeyFile  = Path.of(p.getProperty("nodeKey", "nodekey.json").trim());
        this.nodesTx      = blankToNull(p.getProperty("nodesTx"));
        if (nodesTx != null && !nodesTx.matches("[0-9a-f]{64}"))
            throw new IllegalStateException("nodesTx 必须是 64 位小写 hex：" + nodesTx);
    }

    /** 节点私钥封存目录：与帧日志目录分开（/admin/rejoin 清空数据时不受影响）。 */
    public Path vaultDir() { return home.resolve("vault").resolve(requireNodeId()); }

    // ── 加载 ──────────────────────────────────────────────────────

    /** 读取 ./qccname.properties；不存在时在当前目录生成模板并抛异常（节点启动时据此提示后退出）。 */
    public static QccNameConfig load() {
        Path f = CONFIG_FILE.toAbsolutePath();
        if (!Files.isRegularFile(f)) {
            writeTemplate(f);
            throw new IllegalStateException("未找到配置文件，已在当前目录生成模板 " + f + "，填写 nodeId / type（非创世节点再填 seeds）后重新启动");
        }
        Properties p = new Properties();
        try (InputStream in = Files.newInputStream(f)) {
            p.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException("配置文件读取失败: " + f, e);
        }
        return new QccNameConfig(p, f);
    }

    // ── 节点进程用 ────────────────────────────────────────────────

    public String requireNodeId() {
        if (nodeId == null) throw new IllegalStateException("缺少 nodeId：在配置文件写 nodeId=本机QCC地址，或设置 QccNameConfig.DEFAULT_NODE_ID");
        return nodeId;
    }

    public byte[] requireClusterKey() {
        if (clusterKey == null) throw new IllegalStateException("缺少 clusterKey（64 位 hex，所有节点相同）。可用这个新生成的：" + newKeyHex());
        return clusterKey.clone();
    }

    /** 节点进程：type 必填，且与 seeds 一致。 */
    public Type requireType() {
        if (type == null) throw new IllegalStateException("缺少 type：genesis（第一台）/ production（生产，公网 IPv4）/ backup（备份，IPv6）");
        if (type != Type.GENESIS && seeds.isEmpty())
            throw new IllegalStateException("type=" + type.name().toLowerCase() + " 必须配置 seeds（已在运行的任意节点 IP:端口）；只有第一台用 type=genesis");
        return type;
    }

    /** 判定本机公告地址（每次调用重新枚举网卡；NodeMain 会缓存 60 秒）。 */
    public LocalAddressResolver.Resolved resolveAddress() { return LocalAddressResolver.resolve(advertiseIp); }

    public Path nodeDir() { return QccNamePath.nodeDir(home, requireNodeId()); }
    public Path logDir()  { return home.resolve("logs"); }

    /** 客户端默认连接的节点：第一个 seed，没有则本机。 */
    public String clientNodeUrl() { return seeds.isEmpty() ? "http://127.0.0.1:" + port : seeds.getFirst(); }

    // ── 解析 ──────────────────────────────────────────────────────

    private static byte[] parseKey(String hex) {
        if (hex.length() != 64) throw new IllegalStateException("clusterKey 必须是 64 位 hex（32 字节）");
        return qcc.name.codec.Sha3.fromHex(hex);
    }

    public static String newKeyHex() {
        byte[] k = new byte[32];
        new SecureRandom().nextBytes(k);
        return qcc.name.codec.Sha3.toHex(k);
    }

    private static void checkAddress(String a) {
        String b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        if (a.length() < 25 || a.length() > 64) throw new IllegalStateException("nodeId 不是 QCC 地址：" + a);
        for (char c : a.toCharArray()) if (b58.indexOf(c) < 0) throw new IllegalStateException("nodeId 含非 Base58 字符：" + a);
    }

    private static String trimSlash(String u) { return u.endsWith("/") ? u.substring(0, u.length() - 1) : u; }
    private static String blankToNull(String s) { return s == null || s.isBlank() ? null : s.trim(); }

    static Path writeTemplate(Path f) {
        try {
            Files.createDirectories(f.getParent());
            if (Files.exists(f)) return f;
            try (Writer w = Files.newBufferedWriter(f, StandardCharsets.UTF_8)) {
                w.write("""
                        # qccname 节点配置（P2P）。数据在 ~/qccname/ 下

                        # 本机 QCC 地址
                        nodeId=

                        # 节点间 AES-256-GCM 密钥（下面是新生成的）。所有节点填同一个；不要提交到代码仓库
                        clusterKey=%s

                        # genesis 创世（整个集群只有第一台）/ production 生产（公网 IPv4）/ backup 备份（IPv6）
                        type=production

                        # 已在运行的任意节点 IP:端口，逗号分隔，能连上一个即可；IPv6 写成 [地址]:端口。genesis 留空
                        seeds=

                        # 本机公告 IP；空 = 自动判定（公网 IPv4 优先，否则全局 IPv6）。局域网测试须填本机真实 IP
                        advertiseIp=

                        # 节点私钥：把钱包导出的 nodeId 那一段（address / publicKeyHex / privateKeyHex）存成本目录的 nodekey.json，
                        # 首次启动校验后自动封存并删除该文件。genesis / production 必须有
                        #nodeKey=nodekey.json
                        """.formatted(newKeyHex()));
            }
            return f;
        } catch (IOException e) {
            throw new IllegalStateException("模板写入失败: " + f, e);
        }
    }

    @Override
    public String toString() {
        return "nodeId=" + (nodeId == null ? "（未配置）" : nodeId + "（" + nodeIdSource + "）")
                + "  port=" + port + "  type=" + (type == null ? "（未配置）" : type.name().toLowerCase()) + "  seeds=" + (seeds.isEmpty() ? "（空：创世节点）" : seeds)
                + "  链节点 " + chains.size() + "  instance=" + instanceId + "  [" + source + "]";
    }
}