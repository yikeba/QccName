package qcc.name.core;

import qcc.name.codec.Sha3;
import qcc.name.protocol.ProtocolRoot;

import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * 名字校验与同形字归一化。
 *
 * 【本类不含任何字面量参数】字符集、长度、连字符规则、同形字映射表
 * 全部来自链上引导协议的 params 段。想改规则就得发新协议、换 protocolHash、
 * 创世断裂 —— 改动无法隐藏。这就是"协议参数即应用边界"的落地点。
 *
 * ═══ 同形字为什么必须处理 ═══════════════════════════════════════
 * 字符集是 [a-z0-9-],看起来很安全,但在多数无衬线字体下:
 *   0 与 o、1 与 l、rn 与 m 几乎无法分辨
 * 而 namespace 是 QccS3 的鉴权根和 QccWeb 的站点标识,钓鱼收益很高。
 * 0sn 与 osn、c1aude 与 claude 必须被视为冲突。
 *
 * ═══ 归一化算法(必须精确定义,否则跨实现分歧)══════════════════
 * 单次从左到右扫描,每个位置尝试匹配映射表中的 key,**长键优先**;
 * 匹配到就写出替换值并跳过该 key 的长度;匹配不到就原样写出一个字符。
 * 输出**不再重新扫描** —— 二次扫描可能不收敛(如 a→b、b→a)。
 * 长键优先保证了 "rn" 不会被先当成 "r" 处理。
 */
public final class NameValidator {

    private final Pattern charset;
    private final boolean noLeadingHyphen;
    private final boolean noTrailingHyphen;
    private final boolean noConsecutiveHyphen;
    private final Map<String, String> confusableMap;
    private final int maxConfusableKeyLen;

    public NameValidator(ProtocolRoot root) {
        ProtocolRoot.Params p = root.params();
        this.charset             = Pattern.compile(p.nameCharset());
        this.noLeadingHyphen     = p.nameNoLeadingHyphen();
        this.noTrailingHyphen    = p.nameNoTrailingHyphen();
        this.noConsecutiveHyphen = p.nameNoConsecutiveHyphen();
        this.confusableMap       = p.nameConfusableMap();   // 已是不可变 TreeMap
        int max = 1;
        for (String k : confusableMap.keySet()) {
            if (k.isEmpty()) throw new IllegalStateException("同形字映射表不允许空 key");
            max = Math.max(max, k.length());
        }
        this.maxConfusableKeyLen = max;
    }

    /** 格式是否合法。不合法返回 false,对应 resultCode nameFormat。 */
    public boolean isFormatValid(String name) {
        if (name == null || name.isEmpty()) return false;
        // 大小写:协议字符集是 [a-z0-9-],大写直接不合法。
        // 绝不在这里做 toLowerCase —— 不带 Locale 的 toLowerCase 在土耳其区域
        // 会把 'I' 变成 'ı',是经典的跨环境不确定性来源。
        if (!name.equals(name.toLowerCase(Locale.ROOT))) return false;
        if (!charset.matcher(name).matches()) return false;
        if (noLeadingHyphen  && name.charAt(0) == '-') return false;
        if (noTrailingHyphen && name.charAt(name.length() - 1) == '-') return false;
        if (noConsecutiveHyphen && name.contains("--")) return false;
        return true;
    }

    /** 同形字归一化。见类注释里的算法定义。 */
    public String normalize(String name) {
        StringBuilder out = new StringBuilder(name.length());
        int i = 0, n = name.length();
        while (i < n) {
            String hit = null;
            int tryLen = Math.min(maxConfusableKeyLen, n - i);
            for (int len = tryLen; len >= 1; len--) {          // 长键优先
                String candidate = name.substring(i, i + len);
                String repl = confusableMap.get(candidate);
                if (repl != null) { out.append(repl); i += len; hit = candidate; break; }
            }
            if (hit == null) { out.append(name.charAt(i)); i++; }
        }
        return out.toString();
    }

    /** 名字的规范 key:SHA3-256(UTF-8(name))。 */
    public static String nameHash(String name) { return Sha3.hashUtf8Hex(name); }

    /** 归一化名的 key。两个视觉相似的名字在这里会碰撞,从而被 nameConfusableFree 拦下。 */
    public String normHash(String name) { return Sha3.hashUtf8Hex(normalize(name)); }
}
