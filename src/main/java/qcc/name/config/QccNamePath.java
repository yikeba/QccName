package qcc.name.config;

import java.nio.file.Path;

/**
 * namespace 的目录布局。刻意不复用 qcc.config.QccPath：
 * QCC 节点的恢复策略是清空 ~/qccchain 重同步，namespace 的帧日志是权威数据，不能被连带清掉。
 *
 *   {home}/{nodeId}/frames/   帧日志
 *   {home}/{nodeId}/sigs/     签名库
 */
public final class QccNamePath {

    public static Path nodeDir(Path home, String nodeId) {
        Path qccRoot = Path.of(System.getProperty("user.home"), "qccchain").toAbsolutePath().normalize();
        Path d = home.resolve(nodeId).toAbsolutePath().normalize();
        if (d.startsWith(qccRoot))
            throw new IllegalStateException("namespace 数据目录不能位于 ~/qccchain 之内: " + d);
        return d;
    }

    private QccNamePath() {}
}
