package qcc.name;

/** 自测用的极简断言器：打印每一项，累计失败数，不依赖测试框架。 */
public final class Check {
    private int failed;

    public void ck(boolean cond, String msg) {
        if (!cond) failed++;
        System.out.println((cond ? "  OK   " : "  FAIL ") + msg);
    }

    public boolean throwsAny(Runnable r) {
        try { r.run(); return false; } catch (RuntimeException e) { return true; }
    }

    public int failed() { return failed; }
}
