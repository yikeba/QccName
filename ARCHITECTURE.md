# QCC-Namespace 架构与命名说明

配套代码:第一至三批(codec / protocol / state / core),共 33+26+20 项自测通过。
对应链上引导协议:`dd6eba18d557b4c3a99d4355390021488e052c088f49465ca0f7894109dfcb51`
(交易 `f1134cb5df74dc9256e5604a29322470c532edbd4186e18b24e10834242a8627`,容器 342665)

---

## 1. 一句话骨架

整个系统只有一个入口方法,其余全是它的零件:

```
                     链上引导协议(6116 字节 JSON)
                              │
                     ProtocolLoader 校验 hash
                              ▼
                        ProtocolRoot
                   (参数 + 操作分发表 + 检查顺序)
                              │
   OpInput ──────────────────►│
 (一条操作)                    ▼
                    NameStateMachine.apply()   ← 唯一入口,约 20 行
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         resultCode      StateDelta        execHash
              │               │               │
              │               ▼               ▼
              │          NameState       链式推进
              │         (四张 TreeMap)   (每条都推,含被拒的)
              ▼
        OpLogStore(日志,权威)
```

**日志是权威,状态是派生的。** 崩溃恢复 = 重放日志。不存在"状态与日志不一致"这一整类问题。

---

## 2. 一条 register 走完全程

```
1. 客户端   签名 (opCode=1, blockHeight=H, payload=[name, address])
              签名用 ML-DSA-87,4627 字节

2. API 层   收请求 → 校验格式 → 批量验签(并行,核心之外)
              → 签名本体存 SignatureVault,只留 sigHash(32 字节)
              → 从 ChainView 取 PledgeFact
              → 打上 admitHeight = 当前链高度

3. 日志     OpLogStore.append(envelope) → 分配 seq

4. 核心     NameStateMachine.apply(OpInput)
              ├ opCode 已知?          否 → 43
              ├ sigValid?              否 → 40
              ├ admitHeight - blockHeight 在窗口内?  否 → 41
              ├ 签名者 == 所需角色?    否 → 42
              ├ 协议 ops[0].checks 依次跑:
              │    nameFormat → nameConfusableFree → nameUnique
              │    → addressUnique → pledge
              │  第一个失败即决定 resultCode
              └ 全过 → RegisterHandler.apply() 产出 StateDelta

5. 状态     NameState.apply(delta)          三张表更新
6. 哈希     ExecHasher.advance(...)         execHash 推进一步
7. 收据     ReceiptSigner 签回 (seq, opHash, epochId, admitHeight)   [待做]
8. 封口     EpochBuilder 攒够 → 算 Merkle → 上链锚定               [待做]
```

---

## 3. 每个类一句话

### `qcc.name.codec` —— 字节层,保证确定性

| 类 | 职责 |
|---|---|
| `Sha3` | 全项目唯一的 SHA3-256 入口。多段哈希、快速 hex、严格解码(非法 hex 抛异常不补零) |
| `QccCanonicalWriter` | 规范二进制写入。null≠空串、map 按 UTF-8 字节序排、变长带 uint32-be 长度前缀 |
| `QccCanonicalReader` | 对称读取。全部越界抛异常,有 MAX_FIELD 上界,`finish()` 要求字节被完全消费 |
| `CodecSelfTest` | 一致性向量第一批(20 项) |

### `qcc.name.protocol` —— 引导层,应用边界

| 类 | 职责 |
|---|---|
| `StrictJson` | 严格 JSON 解析。拒绝重复 key / 小数 / null / 注释 / 尾随逗号。**不用 fastjson2** |
| `ProtocolRoot` | 协议的可执行形态。参数、操作分发表、检查顺序、resultCode 全从这里来 |
| `ProtocolLoader` | 按硬编码的 `PROTOCOL_HASH` 从链上取回并校验。Fetcher 可注入,验证者可离线加载 |

### `qcc.name.core` —— 确定性核心,**禁 IO / 禁墙钟 / 禁并发 / 禁哈希容器迭代**

| 类 | 职责 |
|---|---|
| `NameStateMachine` | 唯一入口。`apply(OpInput) → OpResult` |
| `NameState` | 四张 TreeMap:forward / reverse / tombstone / confusable |
| `ForwardRecord` | 一个名字的状态:addresses / owner / incarnation / seq。不可变 |
| `Tombstone` | 释放记录:下一代世代号 + 释放高度。用于冷却期与防接管 |
| `StateDelta` | 一条操作的变更集。编码前排序,与 emit 顺序无关 |
| `OpInput` | 一条操作的完整输入 = 写进日志的那条记录 |
| `OpResult` | resultCode + delta + 推进后的 execHash |
| `ExecHasher` | execHash 逐条推进 |
| `NameValidator` | 字符集、连字符、同形字归一化。**参数全部来自协议,无字面量** |
| `OpHandlers` | 五个操作的实现 + 十项检查的实现 |
| `PledgeFact` | 从链上取回的质押事实,作为输入喂进来 |
| `CoreSelfTest` | 一致性向量第三批(33 项),驱动真协议 |

### `qcc.name.state` —— 持久层

| 类 | 职责 |
|---|---|
| `OpLogStore` | 有序只追加日志。段式 128MB、CRC32、崩溃残尾截断、段间隙拒启动、显式 fsync |
| `StateSelfTest` | 一致性向量第二批(26 项) |

### 待做

| 类 | 职责 |
|---|---|
| `SparseMerkle` / `MerkleProof` | stateRoot 与单条包含/不存在证明 |
| `ChainView` + 两个实现 | 质押事实、公钥、当前高度 |
| `EpochBuilder` / `AnchorPublisher` / `ReceiptSigner` | 封口、上链、收据 |
| `ClientApi` / `SystemApi` | 两类 HTTP 接口 |
| `Replayer` / `VerifyCli` | 独立验证器 —— **整个试点的意义所在** |

---

## 4. 四条设计约束(改代码时不要破坏)

**① 核心不做 IO。** 质押、公钥、高度全部作为 `OpInput` 的一部分传进去。
理由:重放者必须能在离线状态下得到完全相同的结果。

**② 时间的唯一来源是区块高度。** 核心里不允许出现 `System.currentTimeMillis()`。
墙钟不可重放。

**③ 核心里没有哈希容器的迭代。** 全部 TreeMap + 显式 `compareUtf8`。
`HashMap` 的迭代顺序跨 JVM、跨语言都不同,是分歧的头号来源。

**④ 核心里没有数字字面量。** 所有参数从 `ProtocolRoot` 注入。
参数写死在代码里,链上那份协议就只是文档了。

这四条建议用 ArchUnit 在 CI 里强制,不要靠自觉。

---

## 5. 命名:哪些能改,哪些改不了

### 随时可改(不进 hash)

| 现名 | 说明 |
|---|---|
| `qcc.name.*` | 包名 |
| 所有**类名** | `OpLogStore` / `NameStateMachine` / `ExecHasher` … |
| 所有**方法名、字段名** | Java 层的东西一律自由 |
| 文件名、目录名 | `oplog_N.qlog` 等 |

### 必须在协议 v1.0.1 之前定死(进 hash)

| 项 | 现值 | 为什么冻结 |
|---|---|---|
| 操作名 | `register` `bindAddr` `unbindAddr` `transferOwner` `release` | 协议 `ops[].name`,分发表按它匹配 |
| 操作码 | 1 2 3 4 5 | 进 execHash 前像 |
| 检查名 | `nameFormat` `nameConfusableFree` `nameUnique` `addressUnique` `pledge` `maxAddresses` `targetBound` `targetNotOwner` `isLastAddress` `confirmFlag` | 协议 `ops[].checks`,顺序决定 resultCode |
| resultCode | 0/10-13/20-25/30-31/40-43 | 进 execHash |
| StateDelta 类型码 | 1=putForward 2=delForward 3=putReverse 4=delReverse 5=putTombstone 6=putConfusable 7=delConfusable | 进 delta 编码 |
| `ForwardRecord` 字段**顺序** | addresses, owner, incarnation, seq | 进编码 |
| `Tombstone` 字段**顺序** | nextIncarnation, releasedHeight, seq | 进编码 |
| `OpInput` 日志字段**顺序** | opCode, blockHeight, admitHeight, payload, signers, sigHash | 进日志与 execHash |
| 协议字段名 | `execHash` `stateRoot` `epoch` `params` … | 协议文档本身 |

**判断方法很简单:这个字符串或数字会不会被 `QccCanonicalWriter` 写出去?** 会 → 冻结;不会 → 随便改。

---

## 6. 协议 v1.0.1 待补清单

跑通实现之后暴露出来的,**都必须在第一批真实注册之前发**:

1. `namespace.incarnation` —— 世代号现在只在实现里
2. `state.confusable` —— 同形字索引是第四张表,进 Merkle 叶子
3. 同形字**归一化算法** —— 长键优先、单次左到右、输出不重扫
4. `execHash.perOp` 的**分帧规则** —— 现在只写了 `||`,没说变长字段怎么分界
5. `admitHeight` 字段 —— 防重放检查的确定性来源
6. 通用前置检查的**顺序** —— opCode → sigValid → replayWindow → authorized
7. `nameUnique` 里冷却期用 `blockHeight` 判定(而不是当前高度)
8. 质押事实的取得方式(见下,取决于历史查询的结论)

---

## 7. 部署隔离

```
端口   HTTP 9180 / 内部 9181     启动时若命中 QCC 已占端口表则拒绝启动
       QCC 已占:9080 9333 9334 9443 9950 9951 9952 9953 9954

目录   ~/qccname/                独立于 ~/qccchain
         oplog/                  操作日志段
         sigvault/               签名本体
         epoch/                  epoch header
         config/

进程   独立 JVM。绝不调用 QccPath.init()
       同机部署时设独立磁盘卷或目录配额,注册高峰不得影响超级节点出块
```

---

## 8. 一个待决问题

**质押查询没有历史高度维度。** `PledgeContext` 转发给 `BALANCE_query_Pledge` 的参数里没有 height,所以验证者无法查"注册发生时的质押状态"。

三个方向:

| | 做法 | 验证强度 | 成本 |
|---|---|---|---|
| a | 链上加历史状态查询 | 最强 | 改主链 |
| b | leader 把 `PledgeFact` 连同 `admitHeight` 写进操作日志,验证者事后抽查 | 中,偏差**可发现** | 低 |
| c | 用"当前是否仍有效"近似 | 弱 | 最低 |

建议 **b**:验证者虽然不能重算当时的质押,但能拿日志里的记录去链上核对 leader 有没有伪造,而且这条记录被 execHash 覆盖,改不了。
