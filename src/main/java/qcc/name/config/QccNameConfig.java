package qcc.name.config;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

/**
 * 节点配置。不使用启动参数：
 *
 *   1. 代码里的默认值（下面 DEFAULT_*）= 本地开发配置：两个节点、开发链、明文 HTTP
 *   2. 若存在本地配置文件，逐项覆盖默认值（正式部署用这种方式）。查找顺序：
 *        ./qccname.properties
 *        ~/qccname/config/qccname.properties
 *      格式见工程根目录 qccname.properties.example
 *
 * 本地同一台机器跑两个节点时，节点身份由启动类决定（DevNode0 / DevNode1），
 * 其余配置共用；正式部署每台机器一份配置文件，由 node= 指定本机身份。
 */
public final class QccNameConfig {

    // ── 本地开发默认值（直接改这里）───────────────────────────────
    static final boolean DEFAULT_DEV      = true;                       // true：明文 HTTP，协议 hash 可不填
    static final String  DEFAULT_NODE     = "name0";
    static final String  DEFAULT_PEERS    = "name0=http://127.0.0.1:9180,name1=http://127.0.0.1:9182";
    static final String  DEFAULT_CHAIN    = "http://127.0.0.1:9190";    // 开发链；测试链为 https://test.qccio.com
    static final String  DEFAULT_PROTOCOL = "qcc-name-v1.0.0.json";
    static final String  DEFAULT_INSTANCE = "qccname-dev";
    static final String  DEFAULT_HOME     = Path.of(System.getProperty("user.home"), "qccname").toString();
    static final String  DEFAULT_BIND     = "0.0.0.0";
    static final String  DEFAULT_DEV_KEYS = Path.of(System.getProperty("user.home"), "qccname-dev").toString();

    // ── 生效配置 ──────────────────────────────────────────────────
    public final boolean dev;
    public final String  nodeId;
    /** 全部节点，插入顺序即创世序号表 order（term 的主节点 = order[term mod N]）。 */
    public final LinkedHashMap<String, String> peers;
    public final String  chainUrl;
    public final Path    protocolFile;
    /** 期望的协议 hash；为 null 时不校验（仅开发模式允许）。 */
    public final String  protocolHash;
    public final String  instanceId;
    public final Path    home;
    public final String  bind;
    public final String  keystore;       // 生产模式 HTTPS 证书（PKCS12 / .jks）
    public final String  keystorePass;
    public final Path    devKeys;        // DevClient 保存开发用户密钥的目录
    /** 配置来源，打印在启动日志里。 */
    public final String  source;

    private QccNameConfig(Properties p, String source) {
        this.source       = source;
        this.dev          = Boolean.parseBoolean(p.getProperty("dev", String.valueOf(DEFAULT_DEV)));
        this.nodeId       = p.getProperty("node", DEFAULT_NODE).trim();
        this.peers        = parsePeers(p.getProperty("peers", DEFAULT_PEERS));
        this.chainUrl     = trimSlash(p.getProperty("chain", DEFAULT_CHAIN));
        this.protocolFile = Path.of(p.getProperty("protocol", DEFAULT_PROTOCOL));
        this.protocolHash = blankToNull(p.getProperty("protocolHash"));
        this.instanceId   = p.getProperty("instance", DEFAULT_INSTANCE).trim();
        this.home         = Path.of(p.getProperty("home", DEFAULT_HOME));
        this.bind         = p.getProperty("bind", DEFAULT_BIND).trim();
        this.keystore     = blankToNull(p.getProperty("keystore"));
        this.keystorePass = p.getProperty("keystorePass", "");
        this.devKeys      = Path.of(p.getProperty("devKeys", DEFAULT_DEV_KEYS));
        validate();
    }

    /** 读取配置：代码默认值，被本地配置文件（若存在）覆盖。 */
    public static QccNameConfig load() {
        for (Path f : new Path[]{Path.of("qccname.properties"),
                Path.of(System.getProperty("user.home"), "qccname", "config", "qccname.properties")}) {
            if (Files.isRegularFile(f)) {
                Properties p = new Properties();
                try (InputStream in = Files.newInputStream(f)) {
                    p.load(new java.io.InputStreamReader(in, java.nio.charset.StandardCharsets.UTF_8));
                } catch (IOException e) {
                    throw new IllegalStateException("配置文件读取失败: " + f, e);
                }
                return new QccNameConfig(p, f.toAbsolutePath().toString());
            }
        }
        return new QccNameConfig(new Properties(), "代码默认值（未找到 qccname.properties）");
    }

    /** 同一份配置，换成另一个节点身份（本地一台机器跑多个节点时用）。 */
    public QccNameConfig asNode(String id) {
        Properties p = toProperties();
        p.setProperty("node", id);
        return new QccNameConfig(p, source + " · node=" + id);
    }

    public String selfUrl()  { return peers.get(nodeId); }
    public int    selfPort() { return URI.create(selfUrl()).getPort(); }
    public String primaryUrl() { return peers.values().iterator().next(); }
    public Path   nodeDir()  { return QccNamePath.nodeDir(home, nodeId); }

    private void validate() {
        if (!peers.containsKey(nodeId)) throw new IllegalStateException("peers 中没有本节点 " + nodeId + "：" + peers.keySet());
        if (selfPort() < 1) throw new IllegalStateException("本节点 URL 必须带端口: " + selfUrl());
        if (!dev && protocolHash == null) throw new IllegalStateException("生产模式（dev=false）必须配置 protocolHash");
        if (!dev && keystore == null) throw new IllegalStateException("生产模式（dev=false）必须配置 keystore（HTTPS 证书）");
        for (String u : peers.values()) {
            String scheme = URI.create(u).getScheme();
            if (!dev && !"https".equals(scheme)) throw new IllegalStateException("生产模式节点地址必须是 https: " + u);
            if (!"http".equals(scheme) && !"https".equals(scheme)) throw new IllegalStateException("节点地址格式错误: " + u);
        }
    }

    private Properties toProperties() {
        Properties p = new Properties();
        p.setProperty("dev", String.valueOf(dev));
        p.setProperty("node", nodeId);
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : peers.entrySet()) {
            if (sb.length() > 0) sb.append(',');
            sb.append(e.getKey()).append('=').append(e.getValue());
        }
        p.setProperty("peers", sb.toString());
        p.setProperty("chain", chainUrl);
        p.setProperty("protocol", protocolFile.toString());
        if (protocolHash != null) p.setProperty("protocolHash", protocolHash);
        p.setProperty("instance", instanceId);
        p.setProperty("home", home.toString());
        p.setProperty("bind", bind);
        if (keystore != null) p.setProperty("keystore", keystore);
        p.setProperty("keystorePass", keystorePass);
        p.setProperty("devKeys", devKeys.toString());
        return p;
    }

    static LinkedHashMap<String, String> parsePeers(String s) {
        LinkedHashMap<String, String> m = new LinkedHashMap<>();
        for (String kv : s.split(",")) {
            int i = kv.indexOf('=');
            if (i <= 0) throw new IllegalStateException("peers 格式应为 id=url,id=url：" + s);
            m.put(kv.substring(0, i).trim(), trimSlash(kv.substring(i + 1).trim()));
        }
        return m;
    }

    private static String trimSlash(String u) { return u.endsWith("/") ? u.substring(0, u.length() - 1) : u; }
    private static String blankToNull(String s) { return s == null || s.isBlank() ? null : s.trim(); }

    @Override
    public String toString() {
        return (dev ? "开发模式" : "生产模式") + " node=" + nodeId + " peers=" + peers + " chain=" + chainUrl
                + " instance=" + instanceId + " home=" + home + "  [" + source + "]";
    }
}
