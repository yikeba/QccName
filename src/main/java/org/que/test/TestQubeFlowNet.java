package org.que.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.que.core.queBlock.BlockController;
import org.que.core.queData.EntityData;
import org.que.core.queData.QueBaseData;
import org.que.core.queData.QubeDataBaseFactory;
import org.que.core.queData.RuleData;
import org.que.core.queData.TransactionData;
import org.que.core.quecontainer.ContainerManager;
import org.que.protocol.QubeDataProtocol;
import org.que.protocol.QubePacket;
import org.que.util.ToolsUtil;
import org.que.wallet.QubeWallet;
import org.que.wallet.WalletSigner;
import org.que.wallet.WalletSource;

import java.security.Security;

public class TestQubeFlowNet {

    static {
        // BouncyCastle 注册
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            System.out.println(">>> [DemoTest Static Init] BouncyCastle Provider 强制注册成功！");
        }
    }

    public static void main(String[] args) throws Exception {

        // 1. 模拟一个客户端钱包身份
        WalletSource wallet = QubeWallet.generate();
        var privKey = wallet.privateKeyParameters;
        String contractAddress = "QCONTRACT_DEMO_001";

        // 2. 配置本次测试条数
        final int TOTAL = 100_000;  // 先 10_000 / 50_000 也行
        System.out.println("开始模拟发送 " + TOTAL + " 条三大数据（通过 QubePacket 协议）...");

        for (int i = 0; i < TOTAL; i++) {

            // 2.1 构造三大数据之一
            int type = i % 3; // 0=交易，1=实体，2=规则
            QueBaseData originalData;

            if (type == 0) {
                // ---- 交易数据 TransactionData ----
                TransactionData tx = new TransactionData(contractAddress);
                tx.from = wallet.address;                    // 虽然会被覆盖，但保持一致
                tx.to = "Q_RECEIVER_" + (i % 10_000);
                tx.amount = 1000L + i;
                tx.memo = (i % 7 == 0) ? ("交易备注_" + i) : "";
                originalData = tx;

            } else if (type == 1) {
                // ---- 实体数据 EntityData ----
                EntityData e = new EntityData(contractAddress);
                e.owner = wallet.address;
                e.content = "{\"index\":" + i + ",\"demo\":\"entity\"}";
                originalData = e;

            } else {
                // ---- 规则数据 RuleData ----
                RuleData r = new RuleData(contractAddress);
                r.ruleJson = "测试规则描述_" + i + ToolsUtil.getUUID();
                originalData = r;
            }

            // 3. 客户端：用新协议编码成 QubePacket（内部完成签名）
            QubePacket packet = QubeDataProtocol.encodeData(
                    originalData,
                    privKey,
                    wallet.publicKeyHex  // DER 公钥 HEX
            );

            // 4. 服务端：验签 + 解析 + 自动填充 from（根据 publicKey → rawPk → address）
            QueBaseData decodedData = QubeDataProtocol.decodeData(packet);

            // （可选）前几条打印一下检查类型 & from 地址
            if (i < 5) {
                System.out.println("示例数据 [" + i + "] type=" + decodedData.getType()
                        + ", from=" + decodedData.from
                        + ", json=" + QubeDataBaseFactory.toJson(decodedData));
            }

            // 5. 丢入区块控制器，由区块控制器异步出块 & 写容器
            BlockController.receive(decodedData);

            if ((i + 1) % 10_000 == 0) {
                System.out.println("已通过协议发送并接收 " + (i + 1) + " 条数据");
            }
        }

        System.out.println("所有数据已送入 BlockController 队列，等待出块和写入容器...");

        // 6. 给出块线程一些时间完成最后一批（视你实际出块时间可调）
        Thread.sleep(10_000);

        // 7. 强制刷盘当前容器
        ContainerManager.flush();

        System.out.println("测试完成。当前待写区块数 = " + ContainerManager.getPendingBlockCount()
                + "，当前容器序号 = " + ContainerManager.getCurrentContainerSeq());

        // JVM 退出时 ContainerManager 的 shutdown hook 会再做一次 close()
    }
}
