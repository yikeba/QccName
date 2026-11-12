package qcc.name.op;

import qcc.name.codec.QccCanonicalWriter;

/**
 * 删除操作。
 *
 * 签名字符串：
 *   QNS1|unregister|{chain}|{address}|{name}|{timestamp}|{regSeq}
 *
 * regSeq = 该名称本次注册在帧日志里的 seq（verify 响应与注册回执里返回）。
 * 它把这条删除签名绑定到"某一次具体的注册"：用户删除后重新注册，
 * 旧的删除签名因 regSeq 不再匹配而失效，无需 nonce 表即可防重放。
 * 必须由 address（名称当前持有地址）签名。
 */
public final class UnregisterOp extends NameOp {

    public final long regSeq;

    public UnregisterOp(String chain, String address, String name, long timestamp, long regSeq) {
        super(chain, address, name, timestamp);
        this.regSeq = regSeq;
    }

    @Override public int    typeCode() { return TYPE_UNREGISTER; }
    @Override public String opName()   { return "unregister"; }

    @Override
    protected void appendSignFields(StringBuilder sb) {
        sb.append(SIGN_SEP).append(regSeq);
    }

    @Override
    protected void writeTail(QccCanonicalWriter w) {
        w.u64(regSeq);
    }

    @Override
    protected void validateTail() {
        if (regSeq < 1) throw new IllegalArgumentException("regSeq 从 1 开始");
    }
}
