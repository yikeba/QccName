# QCC-Namespace 运维手册（Linux）

> 适用版本：qccname 1.0 · 系统：Ubuntu 24.04 / 26.04（其他发行版需自行核对脚本）
> 本手册覆盖三种部署：**A. 单实例**（一个公开 Namespace）· **B. 单机多实例**（公开 + 企业，同一批服务器）· **C. 企业 Namespace 的发布与维护**（协议、Reserved）。
> 文中以 QCC 官方的两套实例为例：`qccname-qccio`（公开，`.qcc`）和 `qccname-osnsg`（企业，`.osn` / `.osnsg`）。换成你自己的实例名、地址和交易 hash 即可。

---

## 0. 先理解五个概念

| 概念 | 含义 | 在哪里配置 |
|---|---|---|
| **实例（instance）** | 一套独立的 Namespace：一份协议、一个集群、一份数据。公开和企业是两个实例 | `instance=` |
| **集群** | 同一实例的所有节点。节点数不用配置：新节点通过 `seeds` 自动加入，主节点维护成员表 | `clusterKey=`（同实例相同） |
| **节点类型** | `genesis` 创世（每个实例只有第一台）· `production` 核心（参与确认与选主）· `backup` 冗余（只同步、提供查询） | `type=` |
| **引导协议** | 一份 JSON，写着全部规则。发布到 QCC 公链，节点按 hash 加载；交易发送者即该实例的**发布者** | `protocol=` `protocolHash=` `protocolTx=` |
| **Reserved** | 发布者签名上链的管理名表（admin、cto…），优先于注册信息；可换人、冻结、释放 | `Reserved.config`（交易 hash 列表） |

**过半规则**：写入确认和选主都以「成员表中核心节点数」为分母，而不是在线节点数。3 台核心可坏 1 台，5 台可坏 2 台；只有 2 台核心时任何一台故障都无法选主，所以**每个实例至少 3 台核心**。

---

## 1. 准备

### 1.1 服务器

| 项目 | 要求 |
|---|---|
| 系统 | Ubuntu 24.04 / 26.04（root 或可 sudo 的用户） |
| 内存 | 512MB 起（256MB 可运行，约 8 万名称以内）；每多一个实例约多 150MB |
| 网络 | 核心节点用公网 IPv4；IPv6 / 家庭网络适合做 `backup` |
| 分布 | 同一实例的核心节点放在不同服务商 / 机房，避免整体同时故障 |
| Java | 23 以上；脚本发现没有会自动安装 Java 25 |
| 时间 | 必须 NTP 同步（节点间加密消息时间窗 ±60 秒），脚本会自动开启 |

### 1.2 端口

| 端口 | 用途 | 说明 |
|---|---|---|
| 9180/TCP | 公开实例：节点互联 + HTTP API + 网站 | 同实例所有节点互通，对外开放 |
| 9181/TCP | 企业实例（第二个实例） | 每多一个实例用一个新端口 |
| 443/TCP | HTTPS 网站（可选） | 同机只有一个实例能占用；被占用时其他实例自动跳过 HTTPS |

脚本只在**本机防火墙**（ufw / firewalld / iptables）放行端口，**云厂商控制台的安全组需要自己放行**（IPv4 与 IPv6）。

### 1.3 打包（开发机）

```bash
./gradlew selfTest jar          # 先跑全部自测，再打包
# 产物：build/libs/qccname.jar（依赖已打入，一个文件）
```

同一个 `qccname.jar` 用于所有实例，**不需要为不同实例改名**。

### 1.4 每台服务器需要的文件

```
qccname.jar                      # 程序（各实例相同）
qccname.sh                       # 运维脚本（各实例相同）
qccname.properties               # 配置（每个实例一份）
qcc-name-*.json                  # 该实例的引导协议文件（必须和链上逐字节一致）
Reserved.config                  # 仅企业实例需要
```

---

## 2. 方案 A：单实例（一个公开 Namespace）

示例：3 台服务器 S1 / S2 / S3，部署公开实例 `qccname-qccio`。

### 步骤 1 · 生成集群密钥（只做一次）

```bash
openssl rand -hex 32            # 结果填入每台的 clusterKey，三台相同；不要提交到代码仓库
```

### 步骤 2 · 每台服务器放置文件

```bash
sudo mkdir -p /opt/qccname-qccio && cd /opt/qccname-qccio
# 上传：qccname.jar  qccname.sh  qcc-name-public-v1.0.0.json
chmod +x qccname.sh
```

### 步骤 3 · 配置 S1（创世节点）

`/opt/qccname-qccio/qccname.properties`

```properties
nodeId=<S1 的 QCC 地址>
clusterKey=<步骤 1 的 64 位 hex>
type=genesis
seeds=
port=9180
instance=qccname-qccio
protocol=qcc-name-public-v1.0.0.json
protocolHash=b0aac8365988fa86a04b0802dcd682abaa2f59ea3f48cc3cc50ac559772f058c
protocolTx=7a63c86747c75b860479f16fd0b1307f9d78fe4e29169908004b63ed63170ce3
#advertiseIp=                   # 留空自动判定；云主机 1:1 NAT（AWS/GCP/Azure）必须填公网 IP
```

### 步骤 4 · 检查并启动 S1

```bash
./qccname.sh check              # 系统 / Java / 文件 / 时间 / IPv6 / 防火墙
./qccname.sh start
```

启动输出中应看到：

```
协议交易 7a63c86747c75b86… 高度 26730  发布者 QMnGE6…
保留名 启用，发布者 QMnGE6…，交易列表 …/Reserved.config（每 30 秒检查）
集群 …
```

### 步骤 5 · 配置并启动 S2、S3（核心节点）

与 S1 相同，只改三行：

```properties
nodeId=<本机 QCC 地址>
type=production
seeds=<S1 公网 IP>:9180
```

```bash
./qccname.sh start
```

### 步骤 6 · 核对集群

```bash
curl http://<任一节点>:9180/v1/status
```

三台返回的 `term`、`seq`、`execHash` 一致，`cluster.cores` 为 3 个，`role` 一台是主、两台是备。

### 步骤 7 · 核对功能

```bash
curl "http://<IP>:9180/v1/check?name=test.qcc"          # 可注册
curl "http://<IP>:9180/v1/reserved"                     # 公开实例：enabled=true，names 为空
```

---

## 3. 方案 B：单机多实例（公开 + 企业）

同一批服务器上，每个实例**一个应用目录、一个进程、一个端口**，数据完全隔离。

### 3.1 目录与数据布局

```
/opt/qccname-qccio/                      /opt/qccname-osnsg/
  qccname.jar                              qccname.jar            （同一个文件复制一份）
  qccname.sh                               qccname.sh
  qccname.properties  (port=9180)          qccname.properties  (port=9181)
  qcc-name-public-v1.0.0.json              qcc-name-osn-v1.0.0.json
                                           Reserved.config

~/qccname/
  qccname-qccio/{nodeId}/  logs/  qccname.pid      ← 公开实例数据（按 instance 名分目录）
  qccname-osnsg/{nodeId}/  logs/  qccname.pid      ← 企业实例数据
  ssl/   web/   web-osn/   dev/                    ← 同机共用（证书、网站、开发密钥）
```

### 3.2 两个实例的差异

| 配置项 | 公开实例 qccio | 企业实例 osnsg | 说明 |
|---|---|---|---|
| `instance` | `qccname-qccio` | `qccname-osnsg` | 必须不同，同时是数据目录名 |
| `port` | `9180` | `9181` | 必须不同 |
| `clusterKey` | 密钥 A | 密钥 B | 建议不同，配错时不会串到对方集群 |
| `seeds` | `IP:9180` | `IP:9181` | 指向同一实例的端口 |
| `protocol` | `qcc-name-public-v1.0.0.json` | `qcc-name-osn-v1.0.0.json` | |
| `protocolHash` | `b0aac836…058c` | `c5e83193…a9a6` | |
| `protocolTx` | `7a63c867…0ce3` | `3738af48…949b` | |
| `httpsPort` | `443` | `0`（关闭） | 同机只有一个能占 443 |
| `webDir` | `/root/qccname/web` | `/root/qccname/web-osn` | 各自的网站 |
| `nodeId` | 本机地址 | 可与公开实例相同 | 数据已按实例分开 |

### 3.3 企业实例完整配置

`/opt/qccname-osnsg/qccname.properties`

```properties
nodeId=<本机 QCC 地址>
clusterKey=<企业实例专用 64 位 hex>
type=genesis                     # 第一台；其余 production，并填 seeds
#seeds=<第一台 IP>:9181
port=9181
instance=qccname-osnsg
protocol=qcc-name-osn-v1.0.0.json
protocolHash=c5e831931ac2b8a445bc1440be57b5249c8e635f1b329c14a3efdfa8c129a9a6
protocolTx=3738af4899d88efdf1f357143c98379a0cd3505a2a7675b592dc9028cf98949b
httpsPort=0
webDir=/root/qccname/web-osn
#reserved=Reserved.config        # 默认就是应用目录下的这个文件
```

`/opt/qccname-osnsg/Reserved.config`（所有企业节点相同，见第 4.3 节）

```
c5123d5e0d3d6a63b6b7c0376c9851edd21f7e5f742535504a718c6a24126012   # seq 1
```

### 3.4 启动

```bash
cd /opt/qccname-qccio && ./qccname.sh check && ./qccname.sh start
cd /opt/qccname-osnsg && ./qccname.sh check && ./qccname.sh start
```

`check` 在两个目录各执行一次，分别放行 9180 与 9181。

### 3.5 推荐拓扑（7 台服务器）

| 服务器 | qccio（9180） | osnsg（9181） |
|---|---|---|
| S1 | genesis | genesis |
| S2 | production | production |
| S3 | production | production |
| S4–S5 | production | — |
| S6–S7（IPv6） | backup | — |

公开实例 5 核心 + 2 冗余，企业实例 3 核心；一共 7 台服务器、10 个进程。

### 3.6 核对企业实例

```bash
./qccname.sh log                 # 30 秒内出现：[保留名] 已生效 tx c5123d5e…
curl http://<IP>:9181/v1/reserved
curl "http://<IP>:9181/v1/verify?name=dev.osn&address=QMnGE6bPBkvE6M2Dp28V8sTXo8bs5nTHy4"   # match:true, reserved:true
curl "http://<IP>:9181/v1/check?name=admin.osn"                                              # 拒绝：保留名
```

---

## 4. 方案 C：发布企业 Namespace（协议与 Reserved）

### 4.1 发布引导协议

1. 准备协议文件（如 `qcc-name-osn-v1.0.0.json`），**不要用编辑器重新保存**（换行、BOM 都会改变 hash）。
2. 用**企业发布地址**以 QCCData 交易提交原文件。这个地址从此是唯一能发布 Reserved 的地址，以后不能更换（更换 = 重新发布协议 + 数据重置），**建议多签 / 冷钱包**。
3. 核对上链结果：

```bash
TX=<交易 hash>
curl -s http://<QCC 链节点>:9080/v1/hash/$TX | python3 -c "import sys,json,hashlib;o=json.load(sys.stdin);t=json.loads(json.loads(o['data'])['tx']);b=bytes(x&0xFF for x in t['payload']);print('from',t['from']);print(len(b),hashlib.sha3_256(b).hexdigest())"
```

`from` 必须是企业发布地址，hash 必须等于本地文件的 hash（`openssl dgst -sha3-256 文件`）。

4. 节点配置 `protocolHash` 与 `protocolTx`。节点启动时会自动做同样的核对，不一致拒绝启动。

> **QCC 链节点不是都有 SSL**：统一用 `http://<IP>:9080/v1/hash/<tx>`。查不到时返回 `{"ok":false,"error":"transaction not found: …"}`。

### 4.2 编写与发布 Reserved

```json
{
  "protocol": "qcc-name-reserved",
  "version": "1.0.0",
  "nameProtocolHash": "<本实例协议 hash>",
  "seq": 1,
  "prevTx": "",
  "names": {
    "admin.osn":    "QMnGE6bPBkvE6M2Dp28V8sTXo8bs5nTHy4",
    "support.osn":  ""
  },
  "release": []
}
```

| 规则 | 说明 |
|---|---|
| 发布者 | 必须与协议的发布地址相同，否则拒绝（50） |
| `nameProtocolHash` | 必须是**当前**协议的 hash；用错会被拒绝（52） |
| `seq` / `prevTx` | 首版 seq=1、prevTx=""；之后每版 seq+1，prevTx = 上一版交易 hash（53） |
| 生效时间 | 交易所在区块高度；高度必须递增（54） |
| 完整表 | 每版写完整的表；去掉的名字必须写进 `release`，否则拒绝（55） |
| 空地址 `""` | 保留但不绑定（查询结果为不存在） |
| 格式 | UTF-8、LF 换行、无 BOM、字段不多不少；名字的 tag 必须在协议中 |

### 4.3 Reserved.config 规则

```
# ✗ 作废 · 高度 26734 · nameProtocolHash 用错 → 必须注释
#c7d2f8f17af6ca848f6b71d44ec2212419a937840038efd0eeeb7fe78306dddd   # seq 1（错误版）

# ✓ 生效 · 高度 26735
c5123d5e0d3d6a63b6b7c0376c9851edd21f7e5f742535504a718c6a24126012   # seq 1
```

- 每行一个交易 hash，按发布顺序追加；`#` 之后为注释；每 30 秒自动检查，**不需要重启**。
- 节点按行处理，**遇到不合格的一行就停住**，后面的行都不处理 → 发错的交易必须注释掉。
- 文件不是权威：权威是链上交易 + 日志里的 reserve 记录。删掉某行**不会撤销**已生效的版本。
- 所有企业核心节点放同一份（任何一台都可能接任主节点）。

### 4.4 常见管理操作

| 操作 | 新一版 Reserved 怎么写 |
|---|---|
| 管理员换人 | `"admin.osn": "<新地址>"` |
| 新增管理名 | 在 `names` 中加一行 |
| 冻结可疑账户 | `"abc.osn": ""` → 原注册立即移除，名字锁定，形近名同样不能注册 |
| 释放名字 | 从 `names` 删除并写进 `"release": ["abc.osn"]` → 重新开放注册 |

每次：编写 → 发布者上链 → 核对（4.1 第 3 步的命令）→ 追加到 `Reserved.config` → `curl …/v1/reserved` 确认 seq 增加。

---

## 5. 扩容与节点类型

| 操作 | 做法 |
|---|---|
| 加核心节点 | 新机配置 `type=production`、`seeds=<任一已运行节点>:端口`，启动即自动加入 |
| 加冗余节点 | `type=backup`，同上；IPv6 节点 seeds 写成 `[IPv6地址]:端口` |
| 永久下线节点 | 在**主节点本机**：`curl -X POST "http://127.0.0.1:9180/admin/remove?id=<节点地址>"`（否则一直计入过半分母） |
| 更换节点类型 | 先 `/admin/remove`，清空该节点的 `~/qccname/<instance>/<nodeId>/`，改 type 后重新启动 |

---

## 6. HTTPS 与网站

### 6.1 网站

- 把静态文件放进 `webDir`（默认 `~/qccname/web`），HTTP 端口和 HTTPS 端口都会提供；**替换文件即生效**。
- 企业实例用单独目录：`webDir=/root/qccname/web-osn`，放企业介绍页 `index.html` 与协议说明 `osn.html`。

### 6.2 证书（以 Let's Encrypt 为例）

```bash
sudo apt install certbot
sudo certbot certonly --standalone -d ns.example.com      # 需临时空出 80 端口
sudo mkdir -p /root/qccname/ssl
sudo openssl pkcs12 -export \
  -in /etc/letsencrypt/live/ns.example.com/fullchain.pem \
  -inkey /etc/letsencrypt/live/ns.example.com/privkey.pem \
  -out /root/qccname/ssl/qccname.p12 -passout pass:<密码>
```

```properties
httpsPort=443
keystore=/root/qccname/ssl/qccname.p12
keystorePass=<密码>
```

证书续期后重新导出同名文件即可，10 分钟内自动热加载。443 已被同机另一实例占用、或证书缺失时，节点**跳过 HTTPS 继续启动**，日志写明原因。

---

## 7. 开机自启（systemd）

单实例用 `deploy/qccname.service`；多实例用模板单元 `deploy/qccname@.service`（实例名对应 `/opt/qccname-<名称>`）：

```bash
sudo cp deploy/qccname@.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now qccname@qccio qccname@osnsg
systemctl status qccname@osnsg
journalctl -u qccname@osnsg -f
```

> 选择 systemd 后就不要再用 `./qccname.sh start` 启动同一实例（两者会重复启动）；`status` / `log` 仍可使用。

---

## 8. 日常运维

### 8.1 命令（在实例目录下执行）

| 命令 | 作用 |
|---|---|
| `./qccname.sh start` | 环境检查 → 放行防火墙 → 后台启动，显示本次启动日志 |
| `./qccname.sh stop` | 正常退出，10 秒未退出则强制结束 |
| `./qccname.sh restart` | 重启 |
| `./qccname.sh status` | 进程、内存、节点状态、最近一条进度 |
| `./qccname.sh log` | 实时跟踪当天运行日志（Ctrl+C 退出，不影响节点） |
| `./qccname.sh console` | 控制台最后 100 行（启动失败、异常堆栈看这里） |
| `./qccname.sh check` | 只检查环境，不启动 |

内存默认按本机内存自动选择，可覆盖：`QCCNAME_XMX=256m ./qccname.sh start`。

### 8.2 升级程序

1. 开发机 `./gradlew selfTest jar`，全部通过后再发布。
2. 按「**备节点逐台 → 最后主节点**」的顺序：替换 `qccname.jar` → `./qccname.sh restart` → `status` 确认追平后再下一台。
3. 主节点重启时会短暂选主（核心 ≥3 时约 30–40 秒）。

> 只换 jar 不换协议文件时，数据不受影响。**协议文件变化 = 新的 protocolHash = 新实例**，需要重新创世（清空该实例数据目录）。

### 8.3 备份

```bash
tar czf qccname-osnsg-$(date +%F).tgz -C ~/qccname qccname-osnsg /opt/qccname-osnsg/qccname.properties /opt/qccname-osnsg/Reserved.config
```

任何一个健康节点的数据都是完整副本；新节点也可以直接加入集群全量同步，备份主要用于 `clusterKey` 与配置的留存。

---

## 9. 故障处理

| 现象 | 原因 / 处理 |
|---|---|
| 启动报 `protocolTx 的 payload hash … 与本地协议文件 … 不同` | 本地协议文件与链上不一致（被编辑器改过、拿错文件）→ 重新取原文件 |
| 启动反复 `取回 protocolTx 失败（第 N 次，10 秒后重试）` | 链节点不可达 → 检查 `chains=` 与网络；节点会一直重试 |
| 启动报 `链上查不到 protocolTx` | 交易 hash 写错或尚未确认 |
| 日志 `[保留名] … 未生效：DROPPED(50)` | Reserved 不是协议发布者发的 |
| `…(52)` | Reserved 文档格式错，或 `nameProtocolHash` 不是当前协议 |
| `…(53)` | seq 不连续或 prevTx 没有指向上一版 |
| `…(54)` | 区块高度没有递增（文件里的顺序与发布顺序不一致） |
| `…(55)` | 去掉了名字却没写进 release |
| 日志 `HTTPS 跳过：端口 443 已被占用` | 同机另一实例已占用 443，属正常；或改用其他端口 |
| 写入返回 `PENDING` | 确认不足过半（核心宕机过多）→ 恢复任意核心节点 |
| 主节点宕机（核心 ≥3） | 约 30–40 秒自动接班 |
| 主节点宕机（核心 <3） | 不自动接班；必要时在备节点本机 `curl -X POST http://127.0.0.1:<端口>/admin/promote` |
| 旧主恢复 | 自动退位；本地未确认的数据自动清空并重新同步 |
| `/v1/status` 各节点 execHash 不同 | 立即停止写入，保留日志联系开发；常见原因是协议文件或 protocolTx 不一致 |

---

## 10. 上线检查清单

- [ ] 协议已上链，`from` 与 hash 已核对（4.1）
- [ ] 每台 `protocolHash`、`protocolTx` 与链上一致；同实例 `clusterKey` 相同
- [ ] 多实例：`instance`、`port` 各不相同；`seeds` 指向同实例端口
- [ ] `advertiseIp` 不是内网地址（公网部署）
- [ ] 云厂商安全组已放行 9180 / 9181 / 443
- [ ] 每个实例 ≥3 台核心，`/v1/status` 一致
- [ ] 企业实例：`Reserved.config` 已放置，日志出现 `[保留名] 已生效`，`/v1/reserved` 的 seq 正确
- [ ] 发布地址已妥善保管（多签 / 冷钱包）
- [ ] `clusterKey`、配置与 `Reserved.config` 已备份

---

## 附录 A · 配置项

| 键 | 默认 | 说明 |
|---|---|---|
| `nodeId` | 代码默认 | 本机 QCC 地址 |
| `clusterKey` | — | 64 位 hex，同实例相同（必填） |
| `type` | `production` | `genesis` / `production` / `backup` |
| `seeds` | — | 已运行节点 `IP:端口`，逗号分隔；genesis 留空 |
| `advertiseIp` | 自动 | 本机公告 IP |
| `port` | `9180` | 节点互联 + HTTP |
| `bind` | `::` | 监听地址 |
| `instance` | `qccname-test` | 实例名，也是数据目录名 |
| `home` | `~/qccname/<instance>` | 数据目录 |
| `protocol` | `qcc-name-public-v1.0.0.json` | 协议文件 |
| `protocolHash` | — | 协议 hash，公网必填 |
| `protocolTx` | — | 协议上链交易；配置后启用 Reserved |
| `reserved` | `Reserved.config` | Reserved 交易列表文件 |
| `chains` | 代码默认 | QCC 链 API，逗号分隔，按顺序故障切换 |
| `webDir` | `~/qccname/web` | 静态网站目录 |
| `httpsPort` | `443` | `0` 关闭 |
| `keystore` / `keystorePass` | `~/qccname/ssl/qccname.jks` | 证书 |
| `logOps` | `true` | 每次写入 / 同步打印一行 |

## 附录 B · HTTP 接口

| 接口 | 用途 |
|---|---|
| `GET /v1/status` | 节点角色、term、seq、execHash、集群成员 |
| `GET /v1/verify?name=&address=` | 名字与地址是否对应（含 `reserved` 字段与证据） |
| `GET /v1/check?name=` | 注册前预检 |
| `GET /v1/address?address=` | 反查该地址名下的名字（含保留名） |
| `GET /v1/reserved` | 当前 Reserved 表与全部历史 |
| `GET /v1/pubkey?address=` | 地址公钥 |
| `POST /v1/register` · `/v1/unregister` | 注册 / 删除（钱包签名） |
| `POST /admin/promote` · `/admin/remove` · `/admin/rejoin` | 仅本机（127.0.0.1）可调用的管理接口 |
