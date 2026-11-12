package qcc.name.chain;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 本地模拟用的链：内存里的授权质押与公钥表，时钟可手动推进，可模拟链不可达。
 * 授权质押 key 与公链 PledgeRuleManager.authKey 一致：address|tag|credentialHash。
 */
public final class MockChainView implements ChainView {

    private final Map<String, PledgeFact> pledges = new ConcurrentHashMap<>();
    private final Map<String, byte[]>     pubkeys = new ConcurrentHashMap<>();
    private final Map<String, ChainTx>    txs     = new ConcurrentHashMap<>();
    private final AtomicLong clock;
    private volatile boolean down;

    public MockChainView(long startTimeMs) { this.clock = new AtomicLong(startTimeMs); }

    public void putPubkey(String address, byte[] raw)  { pubkeys.put(address, raw.clone()); }

    public void lock(String to, String tag, String txHash, String assetId, long amount, String from) {
        pledges.put(to + "|" + tag + "|" + txHash, new PledgeFact(true, assetId, amount, from));
    }

    /** 发起方撤销：状态直接移除（与公链内存状态机一致，不留历史）。 */
    public void revoke(String to, String tag, String txHash) { pledges.remove(to + "|" + tag + "|" + txHash); }

    public void putTx(ChainTx t) { txs.put(t.txHash(), t); }

    @Override
    public ChainTx tx(String txHash) {
        if (down) throw new ChainUnavailableException("mock chain down");
        return txs.get(txHash);
    }

    public void advance(long ms) { clock.addAndGet(ms); }
    public long now()            { return clock.get(); }
    public void setDown(boolean d) { this.down = d; }

    @Override
    public PledgeFact authPledge(String address, String tag, String credentialHash) {
        if (down) throw new ChainUnavailableException("mock chain down");
        PledgeFact f = pledges.get(address + "|" + tag + "|" + credentialHash);
        return f == null ? PledgeFact.none() : f;
    }

    @Override
    public byte[] pubkeyOf(String address) {
        if (down) throw new ChainUnavailableException("mock chain down");
        byte[] k = pubkeys.get(address);
        return k == null ? null : k.clone();
    }

    @Override
    public long chainTime() {
        if (down) throw new ChainUnavailableException("mock chain down");
        return clock.get();
    }
}
