package qcc.name.node;

/**
 * 注册/删除请求的处理结果。
 *   OK          已写入日志并获得足够的备份确认，操作生效
 *   REJECTED    已写入日志，但按规则拒绝（resultCode 说明原因；拒绝本身可被核对）
 *   PENDING     已写入主节点日志，备份确认不足；待备节点追平后即生效。客户端可用同一请求重试（幂等）
 *   DROPPED     入口丢弃，不进日志（格式、签名、时间窗、质押不满足等）
 *   UNAVAILABLE 主节点或公链暂不可达，可稍后重试
 */
public record SubmitResult(Status status, int resultCode, long seq, String message) {

    public enum Status { OK, REJECTED, PENDING, DROPPED, UNAVAILABLE }

    public static SubmitResult dropped(int code, String msg) { return new SubmitResult(Status.DROPPED, code, 0, msg); }
    public static SubmitResult unavailable(String msg)       { return new SubmitResult(Status.UNAVAILABLE, -1, 0, msg); }

    @Override
    public String toString() {
        return status + (resultCode >= 0 ? "(" + resultCode + ")" : "") + (seq > 0 ? " seq=" + seq : "")
                + (message == null || message.isEmpty() ? "" : " " + message);
    }
}
