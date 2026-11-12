package qcc.name.core;

import qcc.name.op.NameOp;

/**
 * 确定性核心的一条输入 = 帧里记录的全部事实。
 * 核心不做 IO：质押事实与 chainTime 由主节点在核心之外取得，写进帧，回放时原样喂回。
 */
public record FrameInput(NameOp op, boolean pledgeExists, String pledgeAssetId, long pledgeAmount,
                         long chainTime, long seq) {

    public static FrameInput noPledge(NameOp op, long chainTime, long seq) {
        return new FrameInput(op, false, "", 0L, chainTime, seq);
    }
}
