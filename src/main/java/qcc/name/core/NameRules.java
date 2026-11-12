package qcc.name.core;

import qcc.name.protocol.NameProtocol;

import java.util.SortedMap;

/**
 * label 规则与同形字归一化。全部参数来自引导协议，本类不含字面量参数。
 *
 * 归一化算法（协议 params.confusableAlgorithm）：单次从左到右，每个位置按 key
 * 长度从长到短尝试匹配；命中则输出替换值并跳过 key 长度，否则原样输出一个字符；
 * 输出不再重扫（重扫可能不收敛，如 a→b、b→a）。作用域为单个 tag。
 */
public final class NameRules {

    private final NameProtocol p;
    private final SortedMap<String, String> map;
    private final int maxKeyLen;

    public NameRules(NameProtocol p) {
        this.p = p;
        this.map = p.confusableMap;
        int m = 1;
        for (String k : map.keySet()) m = Math.max(m, k.length());
        this.maxKeyLen = m;
    }

    public boolean labelValid(String label) {
        if (label == null) return false;
        int n = label.length();
        if (n < p.labelMinLen || n > p.labelMaxLen) return false;
        for (int i = 0; i < n; i++) if (p.labelAlphabet.indexOf(label.charAt(i)) < 0) return false;
        if (p.labelNoLeadingHyphen && label.charAt(0) == '-') return false;
        if (p.labelNoTrailingHyphen && label.charAt(n - 1) == '-') return false;
        return true;
    }

    public String normalize(String label) {
        StringBuilder out = new StringBuilder(label.length());
        int i = 0, n = label.length();
        while (i < n) {
            boolean hit = false;
            for (int len = Math.min(maxKeyLen, n - i); len >= 1; len--) {
                String r = map.get(label.substring(i, i + len));
                if (r != null) { out.append(r); i += len; hit = true; break; }
            }
            if (!hit) { out.append(label.charAt(i)); i++; }
        }
        return out.toString();
    }

    /** 同形字索引 key：tag|normalize(label)。 */
    public String confusableKey(String tag, String label) { return tag + "|" + normalize(label); }
}
