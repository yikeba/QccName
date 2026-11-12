# QCC-Namespace v1.0 架构说明

名称 `label.tag` ↔ ML-DSA-87 地址。可验证等级 **L1（结果可验证）**。JDK 23 + bcprov 1.81（与 QCC 一致），验签直接用 QCC 的 `DilithiumVerifier`；classpath 上没有 BC 时自动改用 JDK 24+ 原生实现。

## 运行

```bash
./gradlew selfTest      # 全部自测（含两节点模拟）
./gradlew simulate      # 只跑两节点本地模拟
# 或不用 Gradle（工程根目录）：
javac -encoding UTF-8 -d out $(find src -name '*.java')
java -Dstdout.encoding=UTF-8 -cp out qcc.name.AllTests
```

必须在工程根目录运行：会读取 `qcc-meta-v1.0.0.json`、`qcc-name-v1.0.0.json`、`testdata/`。

## 部署（v1.0 公网测试，P2P）

一台服务器一个节点，入口 `qcc.name.node.NodeMain`，无启动参数，只读属性文件。必填 3 项：

```properties
nodeId=本机QCC地址          # 配置文件优先，否则代码 DEFAULT_NODE_ID
clusterKey=64位hex          # 节点间 AES-256-GCM，所有节点相同，不进仓库
seeds=IP:端口,...           # 能连上任意一台即可；第一台（创世）留空
```

其余（port / advertiseIp / role / chains / protocolHash …）均有默认值，见 `qccname.properties.example`、`deploy/DEPLOY.md`。

### 集群（`node/Cluster` + `NameNode`）

| | 说明 |
|---|---|
| 本机地址 | `LocalAddressResolver`：网卡上的公网 IPv4 优先，否则全局 IPv6；或 `advertiseIp` 指定 |
| 角色 | 公网 IPv4 → 核心（确认、投票、接班）；只有 IPv6 / NAT → 冗余（只同步、查询） |
| 加入 | 联系任意 seed 取得成员表 → hello 主节点 → 主节点登记（核心按加入顺序）并广播 |
| 成员表 | 持久化 `数据目录/cluster.json`；(term, ver) 更新者胜出；IP 为软状态，随心跳更新（IPv6 轮换不影响） |
| 心跳 | 主节点每 10 秒 announce 全体；其他节点每 10 秒 hello 主节点：上报地址、追平、分叉检测 |
| 确认数 | 核心 ≥3：过半（4 核心需 2 个 ACK）；核心 <3：min(minBackupAcks, 核心数-1) |
| 接班 | 核心 ≥3：主节点失联 30 秒 + 顺位×10 秒 → 选举，过半同意即当选；核心 <3：手动 promote（防脑裂） |
| 投票条件 | 投票方自己也 ≥15 秒联系不上主节点；本任期未投过票；候选人 (lastTerm, seq) 不落后 |
| 旧主恢复 | 启动探测 / 收到更高 term → 退位；本地有未确认帧 → 自动清空、全量重新同步 |
| 创世安全 | seeds 为空且本地无数据才创世；配了 seeds 连不上只重试，永不自封为主 |

### 节点间加密（`crypto/ClusterCipher`）

```
MAGIC "QNSC" | ver 1 | ts u64 | nonce 12 | AES-256-GCM(ciphertext + tag16)
AAD = MAGIC | ver | ts | nonce | path [| 请求 nonce（仅响应）]
```

- 请求：|now − ts| ≤ 60s，nonce 窗口内不得重复（防重放）；path 进 AAD（不能跨接口挪用）
- 响应：AAD 绑定请求 nonce（不能冒充别的请求的响应）
- 鉴权 = 持有 clusterKey，不依赖 IP 白名单与 HTTPS；解密失败统一 403
- GCM 已是认证加密，不需要再叠加 HMAC（与 QccInternalFrame 的区别）；密钥从配置读取，不写在源码里

### 多链节点（`chain/MultiChainView`）

- 查询从最近成功的节点开始依次尝试，失败节点暂停 30 秒；全部失败 → ChainUnavailable，写入返回 UNAVAILABLE（不误判）
- 公钥查不到时再问另一个节点（新地址可能尚未同步到落后节点）
- 回收（expire）前要求 ≥2 个链节点回答"质押不存在"且没有节点回答"存在"

### 内存（实测，JDK 25，SerialGC）

| 项 | 数值 |
|---|---|
| 每个名称常驻堆 | ≈ 0.8 KB（状态 + 幂等索引，2 万名称重放实测 790 B） |
| 每帧磁盘 | ≈ 4.9 KB（ML-DSA-87 签名 4627 B 占绝大部分） |
| 进程 RSS（-Xmx96m，300 名称，3 节点联调） | ≈ 80 MB |

| VPS | 建议 |
|---|---|
| 256 MB | 可用。默认 `-Xmx128m`，约 8 万名称以内；系统要精简（不跑其他服务），建议加 512 MB swap |
| 512 MB | 推荐。`-Xmx256m`，约 25 万名称 |

磁盘：10 万帧 ≈ 0.5 GB。

开发工具：`qcc.name.dev.DevClient`（importkey / pledge / register / unregister / verify / revoke / status，末尾 `@序号` 指定节点，读同一份配置）；
不连测试链时运行 `qcc.name.dev.DevChainServer`，配置 `chains=http://127.0.0.1:9190`。

| 接口 | 说明 |
|---|---|
| `POST /v1/register` | `{"chain","address","name","timestamp","credentialHash","sig"}`，sig 为 hex |
| `POST /v1/unregister` | `{"chain","address","name","timestamp","regSeq","sig"}` |
| `GET /v1/verify?name=&address=` | `match` true/false + 原因 `status`（MATCH / MISMATCH / NOT_FOUND / REVOKED / UNVERIFIED）+ L1 证据。地址匹配时查链确认授权质押仍有效，撤销即 false |
| `GET /v1/pubkey?address=` | 链上公钥 |
| `GET /v1/status` | term / seq / execHash / 角色 |
| `POST /internal/*` | 节点间接口（frame / pull / heartbeat / submit / cluster），AES-256-GCM 密文，解密失败 403 |
| `POST /admin/promote[?term=N]` | 手动接班（核心 <3 时用），只允许本机 |
| `POST /admin/rejoin?peer=节点地址` | 清空本地数据，全量重新同步（分叉时自动执行），只允许本机 |
| `POST /admin/remove?id=节点地址` | 主节点上移除永久下线的成员，只允许本机 |

限流：`/v1/*` 按来源 IP 每分钟写 60、读 1200（`NameHttpServer.WRITE_PER_MIN / READ_PER_MIN`），节点 IP 与回环不限，超限 429。

服务端按请求字段重建签名字符串再验签，客户端（Flutter）只需拼字符串、签名、发 JSON。

## 引导协议

| 文件 | 状态 | hash |
|---|---|---|
| `qcc-meta-v1.0.0.json` | 已上链（tx `09ea70e0…`，高度 16965） | `a25375d6…46fdf` |
| `qcc-name-v1.0.0.json` | **未上链**，本地调试 | 运行时打印 |

上链后把交易 hash 与协议 hash 填进 `ProtocolLoader.PROTOCOL_TX_HASH / PROTOCOL_HASH`。
链上 payload 是 Java 有符号字节数组，还原时必须 `x & 0xFF`。

## 包结构

| 包 | 职责 |
|---|---|
| `codec` | SHA3-256、规范二进制读写（沿用） |
| `protocol` | `StrictJson` 严格解析；`NameProtocol` 按 qcc-meta/1 校验结构并解析参数；`ProtocolLoader` 校验 hash、从链上取回 |
| `op` | `NameOp` 抽象类 + `RegisterOp` / `UnregisterOp` / `ExpireOp`：签名字符串（`QNS1\|…`）与二进制形态 |
| `crypto` | `MlDsa87`（BC / JDK 原生自动选择）；`ClusterCipher` 节点间 AES-256-GCM |
| `chain` | `ChainView`；`HttpChainView` 单个链节点；`MultiChainView` 多节点故障切换；`MockChainView` 本地模拟 |
| `core` | **确定性核心**：`NameMachine`（按协议顺序跑检查、apply、execHash 链）、`NameState`、`NameRules` |
| `frame` | `NameFrame` 同步帧（约 200 字节）；`FrameCodec` 线格式 `QNSF\|TYPE\|len\|payload` |
| `store` | `FrameStore` = 帧日志 + 签名库（两份 `OpLogStore`，seq 对齐） |
| `node` | `NameNode` 主/备/冗余逻辑；`Transport` 接口 + `InMemoryTransport`；`NodeMain` 启动（日志、10 秒同步定时器） |
| `verify` | `ResultVerifier`（L1 证据核对，任何人可用）；`Replayer`（离线重放） |
| `sim` | `LocalSimulation` 两节点端到端模拟 |
| `http` | 对外接口、限流、`HttpTransport`；`NetSelfTest`（加密 / 冗余节点 / 多链节点，真实 HTTP） |

## 写入流程（主节点）

```
入口：格式 → chain → ±5 分钟时间窗 → 幂等(opHash) → 链上公钥验签
链上事实：chainTime；register 查授权质押 (address, qccio, credentialHash)
核心 evaluate（检查顺序由协议 ops[].checks 决定）
  register   tsMonotonic → tagOpen → pledgeMet → labelFormat → notReserved
             → notConfusable → nameFree → cooldownPassed → addressFree
  unregister tsMonotonic → nameExists → holderMatches → regSeqMatches
  expire     nameExists → holderMatches → credentialMatches → pledgeGone
撞上 13/20 → 查原持有者质押，已撤销则先写 expire 帧回收
不在 loggedRejections 中的拒绝 → 入口丢弃（不进日志）
构帧 → apply → 落盘 → 推送备节点 → ACK ≥ minBackupAcks 才算 OK，否则 PENDING
```

质押检查排在业务检查之前：日志里每一条拒绝帧背后都锁着质押，无成本刷日志不可行。

## 状态

```
records    name          → address | credentialHash | regSeq | regTime
holders    tag|address   → name            （每个地址每个 tag 一个名称）
lastTs     address       → 最近一条入日志的用户操作 timestamp（防重放，删除后保留）
tombs      name          → releasedTime | regSeq   （冷却期 30 天，任何人含原地址）
confusable tag|normLabel → name
```

## 帧与 execHash

```
term u32 | seq u64 | chainTime u64 | result u8 | bytes(op) | hash32(sigHash)
| bool(pledgeExists) | str(assetId) | u64(amount) | hash32(execHash)

execHash  = SHA3-256("QNS-EXEC" || prevExecHash || execHash 之前的全部字节)
execHash0 = SHA3-256("QNS-GENESIS" || protocolHash || utf8(instanceId))
```

## 待确认的假设

1. ~~ML-DSA 签名方式~~：已由 QCC `DilithiumVerifier` 确认 —— 纯 ML-DSA-87、空 context、签 UTF-8 原文（与 Flutter liboqs 一致）。
2. **签名分隔符** `|`（`NameOp.SIGN_SEP`）是否与 QccBaseData.SIGN_SEP 统一。
3. **chainTime**：暂无"最新容器时间戳"接口，`HttpChainView` 暂用单调墙钟。
4. **addresskey 响应末尾 8 字节**的含义（解析时忽略）。
5. **地址 checksum**：未校验，链上取不到公钥即拒绝。
6. 首发 tag：协议中开放了 `qcc`、`osn`、`com`，上链前可删减。

## 尚未实现（下一步）

- 节点钱包签名（钱包托管完成后）：nodeId 认证、verify 响应签名
- 分叉恢复目前为全量重新同步（未做公共前缀截断）
