# qccname v1.0 部署（P2P 公网测试）

> 完整运维手册（单实例 / 单机多实例 / 企业 Reserved 发布）：[docs/OPERATIONS.md](../docs/OPERATIONS.md)

## 1. 打包（开发机）
    ./gradlew selfTest jar
    → build/libs/qccname.jar（依赖已打入）。服务器上放同一目录：
      qccname.sh  qccname.jar  qccname.properties  qcc-name-public-v1.0.0.json（OSN 实例用 qcc-name-osn-v1.0.0.json）
    → ./qccname.sh start（Linux）；Windows：java -Xmx256m -jar qccname.jar

## 2. 每台服务器
1. JDK 23+（JDK 23 依赖 lib/bcprov-jdk18on-1.81.jar，已在包内）
2. 时间同步：`timedatectl set-ntp true`（节点间加密消息时间窗 ±60s）
3. 应用目录下的 `qccname.properties`（数据在 `~/qccname/`）：
   ```properties
   nodeId=本机QCC地址
   clusterKey=所有节点相同的64位hex
   type=production             # 第一台 genesis；IPv4 生产节点 production；IPv6 备份节点 backup
   seeds=45.92.158.123:9180    # genesis 留空；其余写已在运行的任意一台
   ```
4. 防火墙开放 9180/TCP（IPv4 + IPv6）
5. 启动：`./qccname.sh start`（status / log / stop / restart / check）

## 3. 推荐部署顺序（4 台 IPv4 + 2 台 IPv6）
1. IPv4 节点 1：`type=genesis`，seeds 空 → 启动后为主节点
2. IPv4 节点 2、3、4：`type=production`，seeds = 节点 1 → 核心节点
3. IPv6 节点 5、6：`type=backup`，seeds = 任意已运行节点 → 冗余节点
4. 任意节点 `curl http://IP:9180/v1/status`：role / term / seq / execHash 一致，`cluster` 中 4 核心 2 冗余

## 4. 故障与恢复
| 情况 | 行为 |
|---|---|
| 主节点宕机（核心 ≥3） | 约 30–40 秒后接班顺位第一的核心节点自动当选（需过半核心同意） |
| 主节点宕机（核心 <3） | 不自动接班；需要时在备节点本机 `curl -X POST http://127.0.0.1:9180/admin/promote` |
| 旧主恢复 | 启动时探测到新主 → 自动退位；本地未确认的帧 → 自动清空并全量重新同步 |
| 备 / 冗余节点离线恢复 | 直接启动，10 秒内追平 |
| 更换节点类型 | 角色以首次加入为准：先在主节点 `/admin/remove` 该节点，清空其 `~/qccname/{nodeId}/` 后重新加入 |
| 节点永久下线 | 在主节点本机 `curl -X POST "http://127.0.0.1:9180/admin/remove?id=地址"`（否则一直计入过半数） |
| 4 核心中 2 台同时宕机 | 写入返回 PENDING（确认不足过半），恢复任意一台即恢复 |

## 5. 内存
256MB VPS 可运行（-Xmx128m，约 8 万名称以内）；512MB 更稳。
