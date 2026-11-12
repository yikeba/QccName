package qcc.name.op;

import qcc.name.codec.QccCanonicalWriter;
import qcc.name.codec.Sha3;
import qcc.name.protocol.ReservedDoc;

/**
 * 保留名表生效（系统操作，无用户签名）。
 *   QNS1|reserve|{chain}|{publisher}||{timestamp}|{reservedTx}|{height}|{documentHash}
 * 主节点从 Reserved.config 读到新的交易 hash → 向多个 QCC 链节点取回该交易（from / 高度 / payload 一致）
 * → 写一条 reserve 帧。帧里携带完整文档，备节点与回放者只凭日志即可重建，不依赖各自读链的时间。
 *   chain        链上交易的 chain
 *   address      链上交易的 from（必须等于协议发布者）
 *   name         空串（本操作不针对单个名称）
 *   timestamp    链上确认时间 confirmTimestamp
 *   reservedTx   Reserved 文档所在交易 hash
 *   height       该交易所在区块高度（生效点，严格递增）
 *   document     文档原始字节（payload）
 * 可验证性（L1）：任何人可以 GET /v1/hash/{reservedTx} 核对 from、高度与 payload。
 */
public final class ReserveOp extends NameOp {

    /** 结构上限；策略上限为协议 reserved.maxBytes，在核心里检查。 */
    static final int MAX_DOCUMENT = 512 * 1024;

    public final String reservedTx;
    public final long   height;
    private final byte[] document;
    private volatile ReservedDoc parsed;
    private volatile String parseError;

    public ReserveOp(String chain, String publisher, long confirmTimestamp, String reservedTx, long height, byte[] document) {
        super(chain, publisher, "", confirmTimestamp);
        this.reservedTx = reservedTx;
        this.height = height;
        this.document = document == null ? null : document.clone();
    }

    @Override public int     typeCode()   { return TYPE_RESERVE; }
    @Override public String  opName()     { return "reserve"; }
    @Override public boolean userSigned() { return false; }
    @Override protected boolean named()   { return false; }

    public byte[] document()     { return document.clone(); }
    public int    documentSize() { return document.length; }
    public String documentHash() { return Sha3.toHex(Sha3.hash(document)); }

    /** 解析后的文档；结构非法返回 null，原因见 {@link #parseError()}。 */
    public ReservedDoc doc() {
        if (parsed == null && parseError == null) {
            try { parsed = ReservedDoc.parse(document); }
            catch (IllegalArgumentException e) { parseError = e.getMessage(); }
        }
        return parsed;
    }

    public String parseError() { doc(); return parseError; }

    @Override
    protected void appendSignFields(StringBuilder sb) {
        sb.append(SIGN_SEP).append(reservedTx).append(SIGN_SEP).append(height).append(SIGN_SEP).append(documentHash());
    }

    @Override
    protected void writeTail(QccCanonicalWriter w) {
        w.hash32Hex(reservedTx).u64(height).bytes(document);
    }

    @Override
    protected void validateTail() {
        if (reservedTx == null || reservedTx.length() != 64 || !Sha3.isHex32(reservedTx)
                || !reservedTx.equals(reservedTx.toLowerCase(java.util.Locale.ROOT)))
            throw new IllegalArgumentException("reservedTx 必须是 64 位小写 hex");
        if (height <= 0) throw new IllegalArgumentException("height 必须为正");
        if (document == null || document.length == 0 || document.length > MAX_DOCUMENT)
            throw new IllegalArgumentException("Reserved 文档为空或超过 " + MAX_DOCUMENT + " 字节");
    }
}
