package qcc.name.node;

import qcc.name.chain.HttpChainView;
import qcc.name.config.QccNamePath;
import qcc.name.config.QccNamePort;
import qcc.name.crypto.MlDsa87;
import qcc.name.http.HttpTransport;
import qcc.name.http.NameHttpServer;
import qcc.name.protocol.NameProtocol;
import qcc.name.protocol.ProtocolLoader;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Path;
import java.util.*;

/**
 * 节点启动入口。全部配置走 -D 系统属性：
 *
 *   -Dqccname.node=name0                                     本节点 id（必填）
 *   -Dqccname.peers=name0=http://127.0.0.1:9180,name1=http://127.0.0.1:9182
 *                                                            全部节点，顺序即创世序号表 order（必填）
 *   -Dqccname.dev=true                                       开发模式：明文 HTTP；协议 hash 可不填
 *   -Dqccname.chain=http://127.0.0.1:9190                    公链 API（开发链或 https://test.qccio.com）
 *   -Dqccname.protocol=qcc-name-v1.0.0.json                  引导协议文件（未上链前）
 *   -Dqccname.protocolHash=…                                 期望的协议 hash（生产必填）
 *   -Dqccname.instance=qccname-dev                           实例 id（进入创世 execHash）
 *   -Dqccname.home=~/qccname                                 数据根目录，节点数据在 {home}/{node}/
 *   -Dqccname.bind=0.0.0.0                                   监听地址
 *   -Dqccname.keystore=… -Dqccname.keystorePass=…            生产模式 HTTPS 证书
 */
public final class NodeMain {

    public static void main(String[] args) throws Exception {
        boolean dev = Boolean.getBoolean("qccname.dev");
        String nodeId = req("qccname.node");
        LinkedHashMap<String, String> peers = parsePeers(req("qccname.peers"));
        if (!peers.containsKey(nodeId)) throw new IllegalArgumentException("qccname.peers 中没有本节点 " + nodeId);

        String protoHash = System.getProperty("qccname.protocolHash");
        if (!dev && protoHash == null) throw new IllegalArgumentException("生产模式必须指定 qccname.protocolHash");
        NameProtocol p = ProtocolLoader.loadFile(Path.of(System.getProperty("qccname.protocol", "qcc-name-v1.0.0.json")), protoHash);

        String keystore = System.getProperty("qccname.keystore");
        if (!dev && keystore == null) throw new IllegalArgumentException("生产模式必须配置 qccname.keystore（HTTPS 证书）");
        if (dev) keystore = null;

        URI self = URI.create(peers.get(nodeId));
        int port = self.getPort();
        QccNamePort.assertNotQccPort(port, "qccname.peers[" + nodeId + "]");

        HttpChainView chain = new HttpChainView(System.getProperty("qccname.chain", "http://127.0.0.1:9190"));
        HttpTransport net = new HttpTransport(peers);
        Path dir = QccNamePath.nodeDir(nodeId);
        NodeConfig cfg = new NodeConfig(nodeId, dir, new ArrayList<>(peers.keySet()), p,
                System.getProperty("qccname.instance", "qccname-dev"), chain, net, System::currentTimeMillis);
        NameNode node = new NameNode(cfg);

        Set<InetAddress> allowed = new HashSet<>();
        for (String u : peers.values())
            try { allowed.addAll(Arrays.asList(InetAddress.getAllByName(URI.create(u).getHost()))); } catch (Exception ignored) { }

        NameHttpServer http = new NameHttpServer(node, chain,
                new InetSocketAddress(System.getProperty("qccname.bind", "0.0.0.0"), port),
                allowed, keystore, System.getProperty("qccname.keystorePass", ""));
        http.start();

        System.out.println("qccname 节点 " + nodeId + " 已启动  " + (dev ? "【开发模式 明文HTTP】" : "【HTTPS】")
                + " :" + port + "  角色=" + (node.isPrimary() ? "主" : "备（主=" + node.primaryId() + "）"));
        System.out.println("  协议 " + p + (protoHash == null ? "  （未校验 hash）" : ""));
        System.out.println("  签名 " + MlDsa87.source() + "  数据 " + dir + "  已有 " + node.maxSeq() + " 帧");

        // 启动时向其他节点追平（备节点重启后补齐缺口）
        if (!node.isPrimary()) {
            boolean ok = node.catchUp(node.primaryId());
            System.out.println("  向主节点 " + node.primaryId() + " 追平：" + (ok ? "完成" : "主节点暂不可达") + "，当前 " + node.maxSeq() + " 帧");
        }

        Runtime.getRuntime().addShutdownHook(new Thread(() -> { http.stop(); node.close(); }));
    }

    static LinkedHashMap<String, String> parsePeers(String s) {
        LinkedHashMap<String, String> m = new LinkedHashMap<>();
        for (String kv : s.split(",")) {
            int i = kv.indexOf('=');
            if (i <= 0) throw new IllegalArgumentException("qccname.peers 格式应为 id=url,id=url");
            String url = kv.substring(i + 1).trim();
            m.put(kv.substring(0, i).trim(), url.endsWith("/") ? url.substring(0, url.length() - 1) : url);
        }
        return m;
    }

    private static String req(String k) {
        String v = System.getProperty(k);
        if (v == null || v.isEmpty()) throw new IllegalArgumentException("缺少 -D" + k);
        return v;
    }
}
