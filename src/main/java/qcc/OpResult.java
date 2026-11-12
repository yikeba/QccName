package qcc.name.core;

import qcc.name.codec.Sha3;

/**
 * 一条操作的执行结果。
 *
 * 【被拒绝的操作也有结果,也推进 execHash】
 * 如果只有成功的操作进 hash,那么"运营方悄悄丢弃 Alice 的注册"和
 * "Alice 的注册因重名被正当拒绝"会产生完全相同的 execHash —— 审查
 * 在链上不可区分。带上 resultCode 之后,拒绝理由本身变成可验证的:
 * 重放者能独立判断"这条被拒了,码是 nameTaken,我重放到这里状态里
 * 确实已经有这个名字,拒绝正确"。
 */
public record OpResult(long seq, int resultCode, StateDelta delta, byte[] execHash) {

    public static final int OK = 0;

    public boolean ok() { return resultCode == OK; }

    public String execHashHex() { return Sha3.toHex(execHash); }

    @Override
    public String toString() {
        return "OpResult{seq=" + seq + " code=" + resultCode
                + " delta=" + delta.size() + " exec=" + execHashHex().substring(0, 12) + "..}";
    }
}
