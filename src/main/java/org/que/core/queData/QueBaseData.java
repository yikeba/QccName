package org.que.core.queData;

import java.util.UUID;

public abstract class QueBaseData {
    /** 每条数据的唯一 ID（你之后会对这部分做签名） */
    protected String id;
    /** 数据生成时间戳（ms） */
    protected long timestamp;
    /** 返回数据类型：transaction / entity / rule */
    public abstract String getType();
    protected String contractAddress; // ★ 所属合约地址
    /** 获取 ID */
    public String getId() {
        return id;
    }
    /** 获取时间戳 */
    public long getTimestamp() {
        return timestamp;
    }
    /** 所有子类必须实现：用于签名所需的字符串 */
    public abstract String getSignPayload();
    /** 初始化 ID+时间戳（由父类统一生成） */
    protected void initBaseFields(String contractAddress) {
        this.id = UUID.randomUUID().toString().replace("-", "");
        this.timestamp = System.currentTimeMillis();
        this.contractAddress = contractAddress;
    }

}

/*

🟦 QubeChain · JSON 模式 10 大黄金准则（最终版）

以下为你今天开发、测试、构建区块、容器的 最高规则，不得违反。

黄金准则 1：所有链上数据必须继承 QueBaseData

QueBaseData 统一提供：

id（UUID）

timestamp（毫秒）

getType()（transaction/entity/rule）

getSignPayload()（用于签名的内容）

initBaseFields()（统一初始化）

目的是保证所有数据格式统一。

黄金准则 2：三大数据类型结构不变，只改变存储方式

数据类型永远只有三类：

TransactionData（交易数据）

EntityData（实体数据）

RuleData（规则数据）

字段、签名方式、Hash 方式 全部不变，
只是从 byte[] 改为 JSON（可无缝互转）。

黄金准则 3：所有数据必须包含共同字段

每一条数据都必须包含：

        {
        "id": "...",
        "timestamp": 1732760000,
        "type": "transaction/entity/rule"
        }


三类数据的个性化内容（payload）可以不同，
但公共部分绝对不可变。

黄金准则 4：区块 Block 只负责三件事

区块结构永远固定：

承载一批数据（列表）

保存前后区块 hash（prevHash）

计算自身 blockHash（排除签名）

区块 JSON 示例：

        {
        "blockNumber": 1,
        "prevHash": "xxx",
        "dataListHash": "xxx",
        "timestamp": 1732760000,
        "dataList": [...],
        "blockHash": "xxx"
        }


区块不做其它逻辑，不做规则，不做脚本。

黄金准则 5：容器 Container 只负责三件事

容器是区块的集合（冷存储容器），结构固定：

containerId

        blockList

fileHash（内容区 hash）

压缩前/压缩后大小

signature（节点签名）

容器 JSON 示例：

        {
        "containerId": "xxx",
        "blockList": [...],
        "fileHash": "sha256",
        "timestamp": 1732760000,
        "signature": "node_signature"
        }


无论 JSON 模式或 byte 模式，结构永远一致。

黄金准则 6：所有 JSON 序列化必须是“确定性 JSON”

必须满足：

字段顺序固定

不写入 null

数组顺序固定

数字、字符串格式严格一致

必须使用：

fastjson2 + OrderedField


以确保 hash 永远一致，否则区块会失效。

黄金准则 7：构建流程不变，只改变 “输出格式”

流程永远固定：

Testnet（JSON 模式）
数据 → JSON → 区块 → JSON → 容器 → JSON 文件

Mainnet（byte 模式）
数据 → byte[] → 区块 → byte[] → 容器 → byte[] 文件


两者只在序列化层有差异，业务逻辑完全一致。

黄金准则 8：必须提供 JSON ↔ byte[] 通用转换器

接口固定：

        JsonBinaryConverter.jsonToBytes(String json)
JsonBinaryConverter.bytesToJson(byte[] bytes)


未来主网只要替换此层实现即可，不影响任何业务代码。

黄金准则 9：今天必须跑通完整链路（JSON 全流程）

必须完成并通过测试：

随机生成 100 条（交易/实体/规则）
        ↓
构建区块
↓
构建容器
↓
写入 JSON 容器文件
↓
读取容器文件
↓
重新解析 JSON
↓
校验所有 hash
↓
验证所有签名
↓
输出：容器验证成功


这是今天的核心目标。

黄金准则 10：容器文件格式必须遵循三段式

容器文件永远是：

        [Header][JSON 内容][SHA256 尾部校验]


其中：

Header：魔数（magic）+ 版本号

JSON 内容：区块+数据 JSON

Tail：全文件 SHA256（未来可加节点签名+设备指纹）

这是你昨晚使用的容器尾部校验，必须保留。

        🟩 附加：金额黄金准则（特别新增）

因为你刚刚确认金额模型：

内部统一使用 int，代表两位小数（× 100）

例如：

        1.00 → 100

        0.01 → 1

        99.99 → 9999

这是全链统一规则，不允许例外。

        🔥 这是你文档中应该写的 最终版 10 大黄金准则

你完全可以把以上内容复制到你的：

README

DESIGN.md

        文档说明

注释

        系统架构图

今天你写的所有数据类、区块类、容器类，都不能违反以上任何一条。*/
