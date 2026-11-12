# qccname v1.0 部署（公网测试）

## 1. 打包（开发机）
    ./gradlew selfTest installDist
    → build/install/qccname/ 整个目录拷到服务器（或 ./gradlew distZip 得到 zip）

## 2. 每台服务器
1. JDK 23+（与 QCC 相同；JDK 23 依赖 lib/bcprov-jdk18on-1.81.jar，已在包内）
2. 时间同步：`timedatectl set-ntp true`（节点间加密消息时间窗 ±60s，用户请求时间窗 ±5 分钟）
3. 复制 `qccname.properties.example` 为 `qccname.properties`，填写：
   - nodes / observers / clusterKey / chains / protocolHash —— **所有节点一致**
   - self = 本机 QCC 地址（NAT、家庭宽带必须填）
4. 防火墙只开放 qccname 端口（默认 9180，TCP，IPv4 + IPv6）
5. 启动：`bin/qccname`（Linux）、`deploy\qccname-win.bat`（Windows）或 systemd（`deploy/qccname.service`）

## 3. 启动核对
- 各节点启动日志的 **节点表摘要** 一致
- `curl http://IP:9180/v1/status` 各节点 seq、execHash 一致
- 备 / 冗余节点日志出现 `[net] … HTTP 403（clusterKey 不一致或时钟偏差 >60s）` → 检查密钥与 NTP

## 4. 运维
| 操作 | 命令（只能在节点本机执行） |
|---|---|
| 主节点故障，备节点接班 | `curl -X POST "http://127.0.0.1:9180/admin/promote?term=1"`（order[term mod 核心数] 必须是本机） |
| 旧主恢复后重新加入 | `curl -X POST "http://127.0.0.1:9180/admin/rejoin?peer=新主地址"`（清空本地，全量同步） |
| 冗余节点离线恢复 | 直接启动，自动追平 |
| 日志 | `home/logs/qccname-yyyyMMdd.log` |

## 5. 内存
VPS 256MB 可运行（-Xmx128m，实测 300 名称时 RSS ≈ 80MB）。名称数超过约 8 万时调大到 -Xmx160m 并加 swap，或使用 512MB。
