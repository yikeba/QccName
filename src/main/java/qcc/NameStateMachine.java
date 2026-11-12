package qcc.name.core;

import qcc.name.codec.Sha3;
import qcc.name.protocol.ProtocolRoot;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * NameStateMachine —— 确定性核心的唯一入口。
 *
 * ═══ 纪律(由 CI 的 ArchUnit 规则强制)═══════════════════════════
 * 本包内禁止:墙钟、IO、网络、随机数、线程、浮点、哈希容器的迭代、
 * JSON 序列化、以及除 0/1 之外的数字字面量。所有参数来自 ProtocolRoot。
 * 时间的唯一来源是 QCC 区块高度,作为输入传入。
 *
 * ═══ 边界不可逾越,是机制不是主张 ═══════════════════════════════
 * 分发表由 ProtocolRoot.buildDispatch() 从链上协议的 ops 数组构建:
 *   - 协议里没声明的 op,分发表里物理上不存在,代码里写了也调不到
 *   - 代码里没实现的 op,启动就失败,不会等到运行时才发现
 *   - checks 的执行顺序来自协议,不是代码里的书写顺序
 * 改任何一条规则都必须发新协议、换 protocolHash、创世断裂。
 *
 * ═══ 通用前置检查的顺序 ═══════════════════════════════════════════
 *   1. opCode 已知           → 43
 *   2. 签名有效              → 40
 *   3. 防重放窗口            → 41
 *   4. 签名者与所需角色匹配   → 42
 * 然后才是协议 ops[].checks 里列出的业务检查。这个顺序也是协议的一部分,
 * 应该在 v1.0.1 里写死 —— 见本批交付说明。
 */
public final class NameStateMachine {

    private final ProtocolRoot  root;
    private final NameValidator validator;
    private final NameState     state;
    private final ExecHasher    hasher;

    private final Map<Integer, OpHandlers.Handler> dispatch;
    private final Map<Integer, List<String>>       checkOrder;
    private final Map<String, OpHandlers.Check>    checks;

    public NameStateMachine(ProtocolRoot root, byte[] genesisExecHash) {
        this.root      = root;
        this.validator = new NameValidator(root);
        this.state     = new NameState();
        this.hasher    = new ExecHasher(genesisExecHash);
        this.checks    = OpHandlers.checks();

        // 分发表来自协议,不是代码里的 switch
        this.dispatch = root.buildDispatch(OpHandlers.handlers());

        // 每个 op 的 check 顺序也来自协议
        Map<Integer, List<String>> order = new TreeMap<>();
        for (ProtocolRoot.OpSpec spec : root.ops()) {
            for (String checkName : spec.checks())
                if (!checks.containsKey(checkName))
                    throw new IllegalStateException("协议要求检查项 '" + checkName
                            + "' 但本实现没有对应实现 —— 拒绝启动");
            order.put(spec.code(), spec.checks());
        }
        this.checkOrder = java.util.Collections.unmodifiableMap(order);

        assertResultCodesDeclared();
    }

    /**
     * 本实现可能产出的每一个 resultCode,协议里都必须有定义。
     * 少一个就说明代码比协议新 —— 那个码的含义没有上链,验证者无法解释它,
     * 所以拒绝启动。这是边界检查的另一半(另一半是未知字段致命)。
     */
    private void assertResultCodesDeclared() {
        int[] emittable = {
            OpHandlers.OK, OpHandlers.NAME_FORMAT, OpHandlers.NAME_CONFUSABLE,
            OpHandlers.NAME_TAKEN, OpHandlers.NAME_IN_COOLDOWN, OpHandlers.ADDRESS_TAKEN,
            OpHandlers.MAX_ADDRESSES, OpHandlers.TARGET_NOT_BOUND, OpHandlers.TARGET_IS_OWNER,
            OpHandlers.NOT_LAST_ADDRESS, OpHandlers.CONFIRM_FLAG_MISSING,
            OpHandlers.PLEDGE_INSUFFICIENT, OpHandlers.PLEDGE_MISSING,
            OpHandlers.SIG_INVALID, OpHandlers.REPLAY_WINDOW,
            OpHandlers.NOT_AUTHORIZED, OpHandlers.UNKNOWN_OP_CODE
        };
        for (int c : emittable)
            if (!root.resultCodes().containsKey(c))
                throw new IllegalStateException("本实现会产出 resultCode " + c
                        + ",但链上协议未定义它 —— 拒绝启动");
    }

    // ── 唯一的公开方法 ────────────────────────────────────────────

    /**
     * 应用一条操作。纯函数式的对外语义:同样的 (当前状态, 输入) 永远得到
     * 同样的 (resultCode, delta, execHash)。
     *
     * 被拒绝的操作产生空 delta,但**照样推进 execHash**(带上 resultCode)。
     * 这让审查与正当拒绝在链上可区分 —— 见 OpResult 的说明。
     */
    public OpResult apply(OpInput in) {
        int code = evaluate(in);
        StateDelta delta = StateDelta.empty();

        if (code == OpHandlers.OK) {
            OpHandlers.Ctx c = context(in);
            dispatch.get(in.opCode).parse(c);
            delta = dispatch.get(in.opCode).apply(c);
            state.apply(delta);
        }

        byte[] exec = hasher.advance(in.opCode, in.payload, in.sigHash, code, delta);
        return new OpResult(in.seq, code, delta, exec);
    }

    /** 跑完全部检查,返回第一个失败的 resultCode;全过返回 0。 */
    private int evaluate(OpInput in) {
        OpHandlers.Handler h = dispatch.get(in.opCode);
        if (h == null) return OpHandlers.UNKNOWN_OP_CODE;
        if (!in.sigValid) return OpHandlers.SIG_INVALID;

        // 纯函数:只依赖日志里记录的两个高度,重放必然得到相同结果
        if (in.blockHeight > in.admitHeight
                || in.admitHeight - in.blockHeight > antiReplayWindow())
            return OpHandlers.REPLAY_WINDOW;

        OpHandlers.Ctx c = context(in);
        h.parse(c);

        List<String> required = h.requiredSigners(c);
        if (required.isEmpty()) return OpHandlers.TARGET_NOT_BOUND;  // 记录不存在
        if (!required.equals(in.signers)) return OpHandlers.NOT_AUTHORIZED;

        for (String checkName : checkOrder.get(in.opCode)) {
            int r = checks.get(checkName).run(c);
            if (r != OpHandlers.OK) return r;   // 第一个失败即决定 resultCode
        }
        return OpHandlers.OK;
    }

    private OpHandlers.Ctx context(OpInput in) {
        return new OpHandlers.Ctx(state, root, validator, in);
    }

    private long antiReplayWindow() { return root.antiReplayWindowBlocks(); }

    // ── 只读访问 ──────────────────────────────────────────────────

    public NameState  state()        { return state; }
    public byte[]     execHash()     { return hasher.current(); }
    public String     execHashHex()  { return hasher.currentHex(); }
    public String     stateRootHex() { return state.flatRootHex(); }

    /** register 操作要用的名字,供外层在调用前预取质押事实。 */
    public static String peekName(byte[] payload) {
        return new qcc.name.codec.QccCanonicalReader(payload).str();
    }

    public String summary() {
        return "{\"exec\":\"" + Sha3.toHex(hasher.current()).substring(0, 16)
                + "\",\"state\":" + state + "}";
    }
}
