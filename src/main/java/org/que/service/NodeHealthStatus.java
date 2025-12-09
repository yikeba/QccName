package org.que.service;

/**
 * 表示QubeChain网络中一个本地节点服务器的健康状态。
 * 这个类用于共识服务器监控和排序超级节点。
 */
public class NodeHealthStatus {

    // 核心属性
    private final int nodeId;               // 序号：节点的唯一标识符
    private HealthStatus status;             // 服务器状态：节点的健康状态

    // 关键状态指标
    private long latestBlockHeight;         // 最新区块高度：用于同步检查
    private long lastHeartbeatTimestamp;    // 最后心跳时间戳：用于超时判断
    private boolean isCurrentLeader;        // 是否是当前的主节点/出块者

    /**
     * 定义节点的健康状态枚举
     */
    public enum HealthStatus {
        HEALTHY,            // 健康且同步
        LAGGING,            // 滞后，正在同步中
        UNRESPONSIVE,       // 无响应，可能超时
        DEAD                // 死亡或被移除
    }

    // 构造函数
    public NodeHealthStatus(int nodeId, HealthStatus initialStatus) {
        this.nodeId = nodeId;
        this.status = initialStatus;
        this.latestBlockHeight = 0;
        this.lastHeartbeatTimestamp = System.currentTimeMillis();
        this.isCurrentLeader = false;
    }

    // 更新状态的方法 (模拟接收心跳包)
    public void updateStatus(long newBlockHeight) {
        this.status = HealthStatus.HEALTHY;
        this.latestBlockHeight = newBlockHeight;
        this.lastHeartbeatTimestamp = System.currentTimeMillis();
    }

    // 检查是否超时
    public boolean checkTimeout(long timeoutMillis) {
        if (System.currentTimeMillis() - this.lastHeartbeatTimestamp > timeoutMillis) {
            this.status = HealthStatus.UNRESPONSIVE;
            return true;
        }
        return false;
    }

    // ==================== Getters ====================

    public int getNodeId() {
        return nodeId;
    }

    public HealthStatus getStatus() {
        return status;
    }

    public long getLatestBlockHeight() {
        return latestBlockHeight;
    }

    public long getLastHeartbeatTimestamp() {
        return lastHeartbeatTimestamp;
    }

    public boolean isCurrentLeader() {
        return isCurrentLeader;
    }

    // ==================== Setters ====================

    public void setStatus(HealthStatus status) {
        this.status = status;
    }

    public void setIsCurrentLeader(boolean isCurrentLeader) {
        this.isCurrentLeader = isCurrentLeader;
    }

    // ==================== 最终 to JSON / toString 方法 ====================

    /**
     * 将对象信息序列化为 JSON 格式的字符串。
     * 在实际项目中，推荐使用 Jackson 或 Gson 等库进行专业序列化。
     */
    @Override
    public String toString() {
        return "{" +
                "\"nodeId\":" + nodeId +
                ", \"status\":\"" + status.name() + "\"" +
                ", \"latestBlockHeight\":" + latestBlockHeight +
                ", \"lastHeartbeatTimestamp\":" + lastHeartbeatTimestamp +
                ", \"isCurrentLeader\":" + isCurrentLeader +
                "}";
    }

    // 示例用法：
    public static void main(String[] args) throws InterruptedException {
        NodeHealthStatus node1 = new NodeHealthStatus(1, HealthStatus.HEALTHY);
        NodeHealthStatus node2 = new NodeHealthStatus(2, HealthStatus.LAGGING);

        System.out.println("--- 初始状态 ---");
        System.out.println("Node 1: " + node1.toString());
        System.out.println("Node 2: " + node2.toString());

        System.out.println("\n--- 模拟心跳更新 ---");
        Thread.sleep(100);
        node1.updateStatus(1024L);
        node1.setIsCurrentLeader(true);
        System.out.println("Node 1 (Updated): " + node1.toString());

        System.out.println("\n--- 模拟超时判断 ---");
        long timeout = 50; // 50ms 超时
        Thread.sleep(100); // 等待超过 50ms

        if (node2.checkTimeout(timeout)) {
            System.out.println("Node 2 超时! 新状态: " + node2.getStatus().name());
        }
        System.out.println("Node 2 (Final): " + node2.toString());
    }
}