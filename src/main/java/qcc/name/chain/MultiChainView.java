package qcc.name.chain;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

/**
 * 多个 QCC 节点 API 的故障切换视图。
 *
 *   - 普通查询（授权质押 / 公钥）：从最近一次成功的节点开始依次尝试，失败的节点暂停 30 秒
 *   - 公钥查不到（null）时再问一个节点：新地址的公钥可能还没同步到落后节点
 *   - 回收前确认（pledgeGoneConfirmed）：至少 CONFIRMS 个节点都回答"不存在"，且没有任何节点回答"存在"
 *     （只配置了 1 个链节点时降为 1）
 *   - chainTime：本机单调时钟（暂无"最新容器时间戳"接口，见 HttpChainView）
 */
public final class MultiChainView implements ChainView {

    static final long DOWN_MS = 30_000;
    static final int CONFIRMS = 2;

    private final List<HttpChainView> views = new ArrayList<>();
    private final List<String> urls;
    private final long[] downUntil;
    private final AtomicInteger preferred = new AtomicInteger();
    private final AtomicLong lastTime = new AtomicLong();

    public MultiChainView(List<String> urls) {
        if (urls.isEmpty()) throw new IllegalArgumentException("链节点列表为空");
        this.urls = List.copyOf(urls);
        for (String u : urls) views.add(new HttpChainView(u));
        this.downUntil = new long[urls.size()];
    }

    @Override
    public PledgeFact authPledge(String address, String tag, String credentialHash) {
        return call(v -> v.authPledge(address, tag, credentialHash));
    }

    @Override
    public byte[] pubkeyOf(String address) {
        int first = preferred.get();
        byte[] k = call(v -> v.pubkeyOf(address));
        if (k != null || views.size() == 1) return k;
        // 再问一个不同的节点
        for (int i = 1; i < views.size(); i++) {
            int idx = (first + i) % views.size();
            if (isDown(idx)) continue;
            try { return views.get(idx).pubkeyOf(address); }
            catch (ChainUnavailableException e) { markDown(idx); }
        }
        return null;
    }

    @Override
    public long chainTime() {
        long now = System.currentTimeMillis();
        return lastTime.updateAndGet(p -> Math.max(p, now));
    }

    @Override
    public boolean pledgeGoneConfirmed(String address, String tag, String credentialHash) {
        int need = Math.min(CONFIRMS, views.size()), gone = 0;
        for (int i = 0; i < views.size(); i++) {
            int idx = (preferred.get() + i) % views.size();
            try {
                if (views.get(idx).authPledge(address, tag, credentialHash).exists()) return false;   // 任何一个节点说存在 → 不回收
                if (++gone >= need) return true;
            } catch (ChainUnavailableException e) {
                markDown(idx);
            }
        }
        return false;    // 确认数不足：宁可不回收
    }

    /** 当前各链节点状态，打印在启动日志里。 */
    public String describe() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < urls.size(); i++) sb.append(i == 0 ? "" : ", ").append(urls.get(i)).append(isDown(i) ? "(暂停)" : "");
        return sb.toString();
    }

    private <T> T call(Function<HttpChainView, T> fn) {
        int n = views.size(), start = preferred.get();
        ChainUnavailableException last = null;
        for (int pass = 0; pass < 2; pass++) {                 // 第二轮连暂停中的节点也试
            for (int i = 0; i < n; i++) {
                int idx = (start + i) % n;
                if (pass == 0 && isDown(idx)) continue;
                try {
                    T r = fn.apply(views.get(idx));
                    preferred.set(idx);
                    downUntil[idx] = 0;
                    return r;
                } catch (ChainUnavailableException e) {
                    last = e;
                    markDown(idx);
                }
            }
        }
        throw new ChainUnavailableException("全部 " + n + " 个链节点不可达", last);
    }

    private boolean isDown(int i) { return downUntil[i] > System.currentTimeMillis(); }
    private void markDown(int i)   { downUntil[i] = System.currentTimeMillis() + DOWN_MS; }
}
