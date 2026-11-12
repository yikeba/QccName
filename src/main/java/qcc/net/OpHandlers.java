package qcc;

import qcc.core.ForwardRecord;
import qcc.core.Tombstone;
import qcc.data.QccCanonicalReader;
import qcc.data.QccCanonicalWriter;
import qcc.protocol.ProtocolRoot;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 五个操作的实现,以及 check 的注册表。
 * ═══ check 的顺序由协议决定,不由代码决定 ═══════════════════════
 * 一个请求可能同时违反 nameTaken 和 pledgeInsufficient。先检查哪个,
 * 决定了 resultCode,而 resultCode 进 execHash。顺序不定义 → 两个实现
 * 复现出不同的 hash。所以 checks 的顺序来自 OpSpec.checks 数组,
 * 代码里只提供**具名的**检查实现,不决定它们的执行次序。
 * ═══ handler 不直接改状态 ═══════════════════════════════════════
 * 它们只产出 StateDelta。NameState.apply(delta) 是修改状态的唯一入口。
 * 这样"进 execHash 的东西"和"实际改变状态的东西"在结构上就是同一个
 * 对象,不可能出现两者不一致。
 */
public final class OpHandlers {

    // ── resultCode(与链上协议 resultCodes 段一一对应)────────────
    public static final int OK                  = 0;
    public static final int NAME_FORMAT         = 10;
    public static final int NAME_CONFUSABLE     = 11;
    public static final int NAME_TAKEN          = 12;
    public static final int NAME_IN_COOLDOWN    = 13;
    public static final int ADDRESS_TAKEN       = 20;
    public static final int MAX_ADDRESSES       = 21;
    public static final int TARGET_NOT_BOUND    = 22;
    public static final int TARGET_IS_OWNER     = 23;
    public static final int NOT_LAST_ADDRESS    = 24;
    public static final int CONFIRM_FLAG_MISSING= 25;
    public static final int PLEDGE_INSUFFICIENT = 30;
    public static final int PLEDGE_MISSING      = 31;
    public static final int SIG_INVALID         = 40;
    public static final int REPLAY_WINDOW       = 41;
    public static final int NOT_AUTHORIZED      = 42;
    public static final int UNKNOWN_OP_CODE     = 43;

    private OpHandlers() {}

    // ── 上下文 ────────────────────────────────────────────────────

    /** 检查与执行共享的上下文。字段由 handler.parse() 填充。 */
    public static final class Ctx {
        public final NameState     state;
        public final ProtocolRoot root;
        public final NameValidator validator;
        public final OpInput       in;

        // parse() 填充
        public String name;        // 明文名字
        public String nameHash;    // SHA3(utf8(name))
        public String normHash;    // SHA3(utf8(normalize(name)))
        public String target;      // bindAddr/unbindAddr/transferOwner 的目标地址
        public boolean confirm;    // release 的确认标志

        public Ctx(NameState state, ProtocolRoot root, NameValidator v, OpInput in) {
            this.state = state; this.root = root; this.validator = v; this.in = in;
        }

        /** 当前记录。register 之前为 null。 */
        public ForwardRecord record() { return state.forward(nameHash); }
    }

    // ── handler 接口 ──────────────────────────────────────────────

    public interface Handler {
        String name();
        /** 解析 payload 填充 ctx。格式错误直接抛 —— 见下方说明。 */
        void parse(Ctx c);
        /** 本操作要求哪些角色签名,按 OpSpec.signers 的顺序解析成具体地址。 */
        List<String> requiredSigners(Ctx c);
        /** 全部 check 通过后调用,产出变更集。 */
        StateDelta apply(Ctx c);
    }

    // ── payload 编解码工具 ────────────────────────────────────────

    public static byte[] nameAndAddr(String name, String addr) {
        return new QccCanonicalWriter().str(name).str(addr).toBytes();
    }

    public static byte[] nameAndFlag(String name, boolean flag) {
        return new QccCanonicalWriter().str(name).bool(flag).toBytes();
    }

    private static void parseNameAddr(Ctx c) {
        QccCanonicalReader r = new QccCanonicalReader(c.in.payload);
        c.name   = r.str();
        c.target = r.str();
        r.finish();
        // 格式错误在这里**抛异常而不是返回 resultCode**:
        // 一条无法解析的记录不是"用户发了非法请求",而是日志损坏或
        // leader 注入了垃圾。API 层在分配 seq 之前就会拒掉畸形请求,
        // 所以能走到这里的畸形记录只可能是日志被污染 —— 那应该停机,
        // 不应该编造一个 resultCode 把它固化进历史。
        if (c.name == null) throw new IllegalStateException("payload 缺少 name");
        c.nameHash = NameValidator.nameHash(c.name);
        c.normHash = c.validator.normHash(c.name);
    }

    // ── 五个操作 ──────────────────────────────────────────────────

    public static final class Register implements Handler {
        public String name() { return "register"; }
        public void parse(Ctx c) { parseNameAddr(c); }
        public List<String> requiredSigners(Ctx c) { return List.of(c.target); } // firstAddress
        public StateDelta apply(Ctx c) {
            long inc = c.state.nextIncarnation(c.nameHash);
            ForwardRecord rec = new ForwardRecord(List.of(c.target), c.target, inc, c.in.seq);
            return StateDelta.builder()
                    .putForward(c.nameHash, rec)
                    .putReverse(c.target, c.nameHash)
                    .putConfusable(c.normHash, c.nameHash)
                    .build();
        }
    }

    public static final class BindAddr implements Handler {
        public String name() { return "bindAddr"; }
        public void parse(Ctx c) { parseNameAddr(c); }
        public List<String> requiredSigners(Ctx c) {
            ForwardRecord r = c.record();
            return r == null ? List.of() : List.of(r.owner, c.target);   // 双签
        }
        public StateDelta apply(Ctx c) {
            ForwardRecord next = c.record().withAddressAdded(c.target, c.in.seq);
            return StateDelta.builder()
                    .putForward(c.nameHash, next)
                    .putReverse(c.target, c.nameHash)
                    .build();
        }
    }

    public static final class UnbindAddr implements Handler {
        public String name() { return "unbindAddr"; }
        public void parse(Ctx c) { parseNameAddr(c); }
        public List<String> requiredSigners(Ctx c) {
            ForwardRecord r = c.record();
            return r == null ? List.of() : List.of(r.owner);
        }
        public StateDelta apply(Ctx c) {
            ForwardRecord next = c.record().withAddressRemoved(c.target, c.in.seq);
            return StateDelta.builder()
                    .putForward(c.nameHash, next)
                    .delReverse(c.target)
                    .build();
        }
    }

    public static final class TransferOwner implements Handler {
        public String name() { return "transferOwner"; }
        public void parse(Ctx c) { parseNameAddr(c); }
        public List<String> requiredSigners(Ctx c) {
            ForwardRecord r = c.record();
            return r == null ? List.of() : List.of(r.owner);
        }
        public StateDelta apply(Ctx c) {
            return StateDelta.builder()
                    .putForward(c.nameHash, c.record().withOwner(c.target, c.in.seq))
                    .build();
        }
    }

    public static final class Release implements Handler {
        public String name() { return "release"; }
        public void parse(Ctx c) {
            QccCanonicalReader r = new QccCanonicalReader(c.in.payload);
            c.name    = r.str();
            c.confirm = r.bool();
            r.finish();
            if (c.name == null) throw new IllegalStateException("payload 缺少 name");
            c.nameHash = NameValidator.nameHash(c.name);
            c.normHash = c.validator.normHash(c.name);
            ForwardRecord rec = c.state.forward(c.nameHash);
            c.target = (rec == null) ? null : rec.owner;   // release 解绑的是最后一个地址
        }
        public List<String> requiredSigners(Ctx c) {
            ForwardRecord r = c.record();
            return r == null ? List.of() : List.of(r.owner);
        }
        public StateDelta apply(Ctx c) {
            ForwardRecord rec = c.record();
            long nextInc = rec.incarnation + 1;
            return StateDelta.builder()
                    .delForward(c.nameHash)
                    .delReverse(rec.owner)
                    .delConfusable(c.normHash)
                    .putTombstone(c.nameHash,
                            new Tombstone(nextInc, c.in.blockHeight, c.in.seq))
                    .build();
        }
    }

    // ── check 注册表 ──────────────────────────────────────────────

    /** 单项检查。返回 0 表示通过,否则返回对应的 resultCode。 */
    public interface Check { int run(Ctx c); }

    public static Map<String, Check> checks() {
        Map<String, Check> m = new TreeMap<>();

        m.put("nameFormat", c ->
                c.validator.isFormatValid(c.name) ? OK : NAME_FORMAT);

        m.put("nameConfusableFree", c -> {
            String holder = c.state.confusableOwner(c.normHash);
            // 已被自己占用不算冲突(bindAddr 等操作会重复走到这条)
            return (holder == null || holder.equals(c.nameHash)) ? OK : NAME_CONFUSABLE;
        });

        m.put("nameUnique", c -> {
            if (c.state.nameTaken(c.nameHash)) return NAME_TAKEN;
            Tombstone t = c.state.tombstone(c.nameHash);
            if (t != null && !t.cooldownPassed(c.in.blockHeight,
                    c.root.params().releaseCooldownBlocks()))
                return NAME_IN_COOLDOWN;
            return OK;
        });

        m.put("addressUnique", c ->
                c.state.addressTaken(c.target) ? ADDRESS_TAKEN : OK);

        m.put("maxAddresses", c -> {
            ForwardRecord r = c.record();
            if (r == null) return TARGET_NOT_BOUND;
            return r.addresses.size() >= c.root.params().maxAddressesPerName()
                    ? MAX_ADDRESSES : OK;
        });

        m.put("targetBound", c -> {
            ForwardRecord r = c.record();
            if (r == null) return TARGET_NOT_BOUND;
            return r.addresses.contains(c.target) ? OK : TARGET_NOT_BOUND;
        });

        m.put("targetNotOwner", c -> {
            ForwardRecord r = c.record();
            if (r == null) return TARGET_NOT_BOUND;
            return r.owner.equals(c.target) ? TARGET_IS_OWNER : OK;
        });

        m.put("isLastAddress", c -> {
            ForwardRecord r = c.record();
            if (r == null) return TARGET_NOT_BOUND;
            return r.addresses.size() == 1 ? OK : NOT_LAST_ADDRESS;
        });

        m.put("confirmFlag", c -> c.confirm ? OK : CONFIRM_FLAG_MISSING);

        m.put("pledge", c -> {
            if (!c.in.pledge.exists()) return PLEDGE_MISSING;
            return c.in.pledge.satisfies(c.root.params().pledgeAssetId(),
                                         c.root.params().pledgeMinAmount())
                    ? OK : PLEDGE_INSUFFICIENT;
        });

        return java.util.Collections.unmodifiableMap(m);
    }

    /** 五个 handler,按协议里的 name 索引。 */
    public static Map<String, Handler> handlers() {
        Map<String, Handler> m = new TreeMap<>();
        for (Handler h : List.of(new Register(), new BindAddr(), new UnbindAddr(),
                                 new TransferOwner(), new Release()))
            m.put(h.name(), h);
        return java.util.Collections.unmodifiableMap(m);
    }
}
