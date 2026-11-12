package qcc.name.frame;

/**
 * 推送/拉取的单元：帧 + 用户签名（expire 无签名，为空数组）+ 公钥（链上没有该地址公钥时随帧携带，否则为空数组）。
 * 公钥不进 execHash：它由"公钥推导出地址"的关系绑定在地址上，接收方自行校验。
 */
public record FramePacket(NameFrame frame, byte[] signature, byte[] pubkey) {
    public FramePacket {
        if (frame == null || signature == null) throw new IllegalArgumentException("frame/signature 不能为 null");
        if (pubkey == null) pubkey = new byte[0];
    }

    public FramePacket(NameFrame frame, byte[] signature) { this(frame, signature, new byte[0]); }
}
