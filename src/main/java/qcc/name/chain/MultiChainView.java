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

    /**
     * 授权质押：回答"存在"直接采用；回答"不存在"时再问另一个节点复核 —— 落后 / 故障节点
     * 不会让正常用户的注册被拒、verify 被误判为 REVOKED。
     */
    @Override
    public PledgeFact authPledge(String address, String tag, String credentialHash) {
        PledgeFact f = call(v -> v.authPledge(address, tag, credentialHash));
        if (f.exists() || views.size() == 1) return f;
        int used = preferred.get();
        for (int i = 1; i < views.size(); i++) {
            int idx = (used + i) % views.size();
            if (idx == used || isDown(idx)) continue;
            try {
                PledgeFact g = views.get(idx).authPledge(address, tag, credentialHash);
                if (g.exists()) System.err.println("[chain] ⚠ " + urls.get(used) + " 回答质押不存在，" + urls.get(idx) + " 回答存在 —— 前者可能落后");
                return g.exists() ? g : f;
            } catch (ChainUnavailableException e) {
                markDown(idx);
            }
        }
        return f;
    }

    /**
     * 公钥：任一节点返回即用。至少 min(2, 节点数) 个节点明确回答"查不到"才返回 null（→ 入口丢弃）；
     * 确认数不足（其余不可达）时抛 ChainUnavailable（→ UNAVAILABLE，客户端可重试），
     * 避免落后节点或网络抖动把正常用户的请求当成"地址无公钥"丢弃。
     */
    @Override
    public byte[] pubkeyOf(String address) {
        int n = views.size(), start = preferred.get(), notFound = 0;
        ChainUnavailableException last = null;
        for (int i = 0; i < n; i++) {
            int idx = (start + i) % n;
            try {
                byte[] k = views.get(idx).pubkeyOf(address);
                downUntil[idx] = 0;
                if (k != null) { preferred.set(idx); return k; }
                notFound++;
            } catch (ChainUnavailableException e) {
                last = e;
                markDown(idx);
            }
        }
        if (notFound >= Math.min(CONFIRMS, n)) return null;
        throw new ChainUnavailableException("公钥查询：" + notFound + "/" + n + " 个链节点回答查不到，其余不可达", last);
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

    /**
     * 交易：至少 min(2, 节点数) 个链节点给出完全一致的回答（from / 高度 / payload），且没有节点给出不同的内容。
     * 全部明确回答"查不到"才返回 null；其余情况（确认数不足、内容不一致）抛 ChainUnavailableException。
     */
    @Override
    public ChainTx tx(String txHash) {
        int n = views.size(), need = Math.min(CONFIRMS, n), same = 0, notFound = 0;
        ChainTx first = null;
        ChainUnavailableException last = null;
        for (int i = 0; i < n; i++) {
            int idx = (preferred.get() + i) % n;
            try {
                ChainTx t = views.get(idx).tx(txHash);
                downUntil[idx] = 0;
                if (t == null) { notFound++; continue; }
                if (first == null) first = t;
                else if (!first.sameAs(t))
                    throw new ChainUnavailableException("交易 " + txHash + " 在不同链节点上内容不一致（" + urls.get(idx) + "）");
                if (++same >= need && notFound == 0) return first;
            } catch (ChainUnavailableException e) {
                if (e.getMessage() != null && e.getMessage().contains("内容不一致")) throw e;
                last = e;
                markDown(idx);
            }
        }
        if (first == null && notFound >= need) return null;
        if (first != null && same >= need) return first;          // 有落后节点答"查不到"，但已有足够节点一致确认
        throw new ChainUnavailableException("交易 " + txHash + "：一致确认 " + same + "/" + need + "，查不到 " + notFound, last);
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
