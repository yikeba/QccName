package qcc.name;

/**
 * 全部自测，串行执行。需在工程根目录运行（读取 qcc-*.json 与 testdata/），JDK 24+。
 *   java -Dstdout.encoding=UTF-8 -cp build/classes/java/main qcc.name.AllTests
 */
public final class AllTests {

    interface Suite { int run(String[] a) throws Exception; }

    public static void main(String[] args) throws Exception {
        Object[][] suites = {
                {"codec    规范二进制与 SHA3",   (Suite) qcc.name.codec.CodecSelfTest::run},
                {"op       签名字符串与二进制",  (Suite) qcc.name.op.NameOpSelfTest::run},
                {"protocol 引导协议与边界",      (Suite) qcc.name.protocol.ProtocolSelfTest::run},
                {"frame    同步帧与线格式",      (Suite) qcc.name.frame.FrameSelfTest::run},
                {"core     确定性核心",          (Suite) qcc.name.core.CoreSelfTest::run},
                {"sim      两节点本地模拟",      (Suite) qcc.name.sim.LocalSimulation::run},
                {"net      加密通讯 / 冗余节点 / 多链节点", (Suite) qcc.name.http.NetSelfTest::run},
                {"cluster  P2P 加入 / 自动选举 / 分叉恢复", (Suite) qcc.name.node.ClusterSelfTest::run},
                {"keys     0 资产钱包公钥（推导 / 缓存 / 同步）", (Suite) qcc.name.node.KeySelfTest::run},
                {"vault    节点私钥导入 / 封存 / 还原", (Suite) qcc.name.crypto.VaultSelfTest::run},
        };
        int pass = 0, fail = 0;
        long t0 = System.currentTimeMillis();
        for (Object[] s : suites) {
            System.out.println("\n━━━━ " + s[0] + " " + "━".repeat(40));
            int f;
            try {
                f = ((Suite) s[1]).run(new String[0]);
            } catch (Throwable e) {
                e.printStackTrace(System.out);
                f = 1;
            }
            if (f == 0) pass++; else fail++;
            System.out.println(f == 0 ? "  ✓ 全部通过" : "  ✗ 失败 " + f + " 项");
        }
        System.out.println("\n━━━━ " + suites.length + " 套 / 通过 " + pass + " / 失败 " + fail
                + " / 耗时 " + (System.currentTimeMillis() - t0) + " ms");
        if (fail != 0) System.exit(1);
    }
}