package qcc.name.node;

import qcc.name.chain.ChainTx;
import qcc.name.chain.ChainUnavailableException;
import qcc.name.chain.ChainView;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Reserved.config 监视器：每行一个 Reserved 文档的交易 hash，按发布顺序追加（# 开头或行尾 # 为注释）。
 *
 *   主节点：按文件顺序找出尚未生效的交易 → 向多个链节点取回（一致确认）→ 写 reserve 帧；
 *           任何一条失败就停在那一条（版本之间靠 seq / prevTx 串成链，不能跳过），下次再试。
 *   其他节点：只从日志同步，本文件仅用于显示"还有几条待主节点生效"。
 *
 * 文件不是权威：权威是链上交易 + 日志里的 reserve 帧。删掉文件里的行不会撤销已生效的版本；
 * 要改变保留名，只能由发布者在链上发新版本，再把交易 hash 追加到本文件。
 */
public final class ReservedWatcher {

    private final NameNode node;
    private final ChainView chain;
    private final Path file;
    private String lastNote = "";

    public ReservedWatcher(NameNode node, ChainView chain, Path file) {
        this.node = node;
        this.chain = chain;
        this.file = file;
    }

    /** 读取文件中的交易 hash（保持顺序，去重）。文件不存在返回空表。 */
    public static List<String> readList(Path file) throws IOException {
        List<String> out = new ArrayList<>();
        if (!Files.isRegularFile(file)) return out;
        int no = 0;
        for (String raw : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            no++;
            String line = raw;
            int h = line.indexOf('#');
            if (h >= 0) line = line.substring(0, h);
            line = line.strip().toLowerCase();
            if (line.isEmpty()) continue;
            if (!line.matches("[0-9a-f]{64}"))
                throw new IOException(file + " 第 " + no + " 行不是 64 位 hex 交易 hash: " + raw.strip());
            if (!out.contains(line)) out.add(line);
        }
        return out;
    }

    public void tick() {
        List<String> list;
        try {
            list = readList(file);
        } catch (IOException e) {
            note("⚠ 读取 " + file + " 失败：" + e.getMessage());
            return;
        }
        if (!node.protocol().reservedEnabled()) {
            if (!list.isEmpty()) note("⚠ " + file + " 有 " + list.size() + " 条交易，但未配置 protocolTx（Reserved 关闭），已忽略");
            return;
        }
        List<String> pending = new ArrayList<>();
        for (String h : list) if (!node.reservedApplied(h)) pending.add(h);
        if (pending.isEmpty()) { note(""); return; }
        if (!node.isPrimary()) {
            note(pending.size() + " 条 Reserved 交易待主节点生效（本机从日志同步）");
            return;
        }
        for (String h : pending) {
            ChainTx tx;
            try {
                tx = chain.tx(h);
            } catch (ChainUnavailableException e) {
                note("⚠ 取回 Reserved 交易 " + h.substring(0, 16) + "… 失败，稍后重试：" + e.getMessage());
                return;
            }
            if (tx == null) { note("⚠ 链上查不到 Reserved 交易 " + h + "（尚未确认？）"); return; }
            SubmitResult r = node.submitReserve(tx);
            if (r.status() == SubmitResult.Status.OK || r.status() == SubmitResult.Status.PENDING) {
                System.out.println("[保留名] 已生效 tx " + h.substring(0, 16) + "… 高度 " + tx.height() + " 发布者 " + tx.from()
                        + "  → " + r.status() + " seq=" + r.seq());
                lastNote = "";
                continue;
            }
            note("⚠ Reserved 交易 " + h.substring(0, 16) + "… 未生效：" + r.status() + "(" + r.resultCode() + ") " + r.message()
                    + "  —— 停在这一条，后面的不处理");
            return;
        }
    }

    /** 同样的提示只打印一次。 */
    private void note(String msg) {
        if (Objects.equals(msg, lastNote)) return;
        lastNote = msg;
        if (!msg.isEmpty()) System.out.println("[保留名] " + msg);
    }
}
