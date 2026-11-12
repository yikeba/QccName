package qcc.name.core;

/**
 * 结果码。数值与含义由引导协议 resultCodes 段定义；这里只是给代码用的名字。
 * NameProtocol 启动时检查 ALL 中每个码都在协议里有定义，少一个就拒绝启动。
 */
public final class ResultCode {
    public static final int OK                  = 0;
    public static final int LABEL_FORMAT        = 10;
    public static final int RESERVED            = 11;
    public static final int CONFUSABLE          = 12;
    public static final int NAME_TAKEN          = 13;
    public static final int COOLDOWN            = 14;
    public static final int TAG_NOT_OPEN        = 15;
    public static final int ADDRESS_HAS_NAME    = 20;
    public static final int TS_NOT_MONOTONIC    = 21;
    public static final int PLEDGE_NOT_MET      = 30;
    public static final int NAME_NOT_FOUND      = 40;
    public static final int HOLDER_MISMATCH     = 41;
    public static final int REGSEQ_MISMATCH     = 42;
    public static final int CREDENTIAL_MISMATCH = 43;
    public static final int PLEDGE_STILL_VALID  = 44;
    public static final int RESERVE_PUBLISHER   = 50;
    public static final int RESERVE_CHAIN       = 51;
    public static final int RESERVE_DOCUMENT    = 52;
    public static final int RESERVE_SEQ         = 53;
    public static final int RESERVE_HEIGHT      = 54;
    public static final int RESERVE_DROPS_NAME  = 55;

    public static final int[] ALL = {OK, LABEL_FORMAT, RESERVED, CONFUSABLE, NAME_TAKEN, COOLDOWN,
            TAG_NOT_OPEN, ADDRESS_HAS_NAME, TS_NOT_MONOTONIC, PLEDGE_NOT_MET, NAME_NOT_FOUND,
            HOLDER_MISMATCH, REGSEQ_MISMATCH, CREDENTIAL_MISMATCH, PLEDGE_STILL_VALID,
            RESERVE_PUBLISHER, RESERVE_CHAIN, RESERVE_DOCUMENT, RESERVE_SEQ, RESERVE_HEIGHT, RESERVE_DROPS_NAME};

    private ResultCode() {}
}
