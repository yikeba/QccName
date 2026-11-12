package qcc.name.verify;

import qcc.name.chain.ChainView;
import qcc.name.codec.Sha3;
import qcc.name.core.NameMachine;
import qcc.name.crypto.MlDsa87;
import qcc.name.crypto.QccAddress;
import qcc.name.frame.FramePacket;
import qcc.name.protocol.NameProtocol;
import qcc.name.store.FrameStore;

import java.nio.file.Path;

/**
 * 离线重放：拿一份帧日志目录（frames/ + sigs/），在本机从创世重放到末尾。
 * 每一帧的结果码与 execHash 都要与重算一致；给了 chain 则同时验证用户签名。
 * 用于节点间一致性核对与故障排查（v1.0 不对公众开放帧日志）。
 */
public final class Replayer {

    public record Result(long frames, String execHash, String stateDigest, long sigChecked) {}

    private Replayer() {}

    public static Result replay(Path dataDir, NameProtocol p, String instanceId, ChainView chainOrNull) {
        try (FrameStore store = new FrameStore(dataDir)) {
            NameMachine m = new NameMachine(p, instanceId);
            long sigs = 0;
            java.util.Map<String, byte[]> known = new java.util.HashMap<>();   // 帧里携带过的公钥（0 资产钱包）
            for (long s = 1; s <= store.maxSeq(); s++) {
                FramePacket pkt = store.packet(s);
                if (chainOrNull != null && pkt.frame().op().userSigned()) {
                    String addr = pkt.frame().op().address;
                    byte[] pk = pkt.pubkey().length > 0 && QccAddress.matches(pkt.pubkey(), addr)
                            ? pkt.pubkey() : chainOrNull.pubkeyOf(addr);
                    if (pk != null && pkt.pubkey().length > 0) known.put(addr, pk);
                    if (pk == null) pk = known.get(addr);
                    if (pk == null || !MlDsa87.verify(pk, pkt.frame().op().signBytes(), pkt.signature())
                            || !Sha3.equalsConstantTime(Sha3.hash(pkt.signature()), pkt.frame().sigHash))
                        throw new IllegalStateException("签名校验失败 seq=" + s);
                    sigs++;
                }
                m.apply(pkt.frame());
            }
            return new Result(store.maxSeq(), m.execHex(), m.state().digest(), sigs);
        }
    }
}
