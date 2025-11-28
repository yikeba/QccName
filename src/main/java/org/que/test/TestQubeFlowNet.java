package org.que.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.que.core.queBlock.BlockController;
import org.que.core.queData.EntityData;
import org.que.core.queData.QueBaseData;
import org.que.core.queData.RuleData;
import org.que.core.queData.TransactionData;
import org.que.core.quecontainer.ContainerManager;
import org.que.protocol.QubeDataProtocol;
import org.que.protocol.QubePacket;
import org.que.wallet.QubeWallet;
import org.que.wallet.QubeWallet.Wallet;

import java.security.Security;
import java.util.Random;

public class TestQubeFlowNet {

    static {
        // 确保 BouncyCastle 注册（你之前已经这么干过）
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            System.out.println(">>> [Static Init] BouncyCastle Provider 注册成功");
        }
    }

    public static void main(String[] args) throws Exception {

        // 1. 模拟一个钱包（客户端身份）
        Wallet wallet = QubeWallet.QubeWallet();
        DilithiumPrivateKeyParameters privKey = wallet.privateKeyParameters;
        byte[] pubKeyBytes = hexToBytes(wallet.publicKeyHex);

        String contractAddress = "QCONTRACT_DEMO_001";

        // 2. 配置本次测试条数
        final int TOTAL = 10_000;   // 你要压测就 10000，先小点可以改成 1000 看效果
       // final int TOTAL = 10;   // 你要压测就 10000，先小点可以改成 1000 看效果
       // Random random = new Random();

        System.out.println("开始模拟发送 " + TOTAL + " 条三大数据（通过 QubePacket 协议）...");

        for (int i = 0; i < TOTAL; i++) {

            // 2.1 随机选择一种数据类型：0=交易，1=实体，2=规则
            int type = i % 3;  // 你可以改成 random.nextInt(3) 随机
            QueBaseData originalData;

            if (type == 0) {
                // ---- 交易数据 TransactionData ----
                TransactionData tx = new TransactionData(contractAddress);
                tx.from = wallet.address;
                tx.to = "Q_RECEIVER_" + (i % 100);
                tx.amount = 1000L + i; // 随便一个 amount
                // 每 5 笔加一个 memo，用来测试 memo 手续费逻辑
                tx.memo = (i % 5 == 0) ? ("交易备注_" + i) : "";
                tx.publicKey = wallet.publicKeyHex;
                tx.sign(privKey);
                originalData = tx;

            } else if (type == 1) {
                // ---- 实体数据 EntityData ----
                EntityData e = new EntityData(contractAddress);
                e.owner = wallet.address;
                e.content = "{\"index\":" + i + ",\"demo\":\"entity\"}";
                e.publicKey = wallet.publicKeyHex;
                e.sign(privKey);
                originalData = e;

            } else {
                // ---- 规则数据 RuleData ----
                RuleData r = new RuleData(contractAddress);
                r.ruleCode = "RULE_" + i;
                r.description = "测试规则描述_" + i;
                r.publicKey = wallet.publicKeyHex;
                r.sign(privKey);
                originalData = r;
            }

            // 3. 客户端：把 QueBaseData 编码成 QubePacket（签名 + 公钥 + payload）
            QubePacket packet = QubeDataProtocol.encodeData(originalData, privKey, pubKeyBytes);

            // 4. 模拟“网络传输”：发送的是 packet.toBytes()
            byte[] networkBytes = packet.toBytes();

            // 5. 服务器端：收到字节 → parse 成 QubePacket
            QubePacket receivedPacket = QubePacket.parse(networkBytes);

            // 6. 服务器端：用协议还原三大数据对象（内部会做 verify）
            QueBaseData decodedData = QubeDataProtocol.decodeData(receivedPacket);

            // （可选）检查一下类型是否正常
            if (i < 5) {
                System.out.println("示例数据 [" + i + "] = " + decodedData);
            }

            // 7. 丢给区块控制器，由区块控制器决定 3 秒出块、队列等
            BlockController.receive(decodedData);

            if ((i + 1) % 1000 == 0) {
                System.out.println("已通过协议发送并接收 " + (i + 1) + " 条数据");
            }
        }

        System.out.println("所有数据已送入 BlockController 队列，等待出块和写入容器...");

        // 8. 给 BlockController 的出块线程一点时间把最后一批处理完
        Thread.sleep(10_000);

        // 9. 强制刷盘当前容器
        ContainerManager.flush();

        System.out.println("测试完成。当前待写区块数 = " + ContainerManager.getPendingBlockCount()
                + "，当前容器序号 = " + ContainerManager.getCurrentContainerSeq());

        // 注意：ContainerManager 有 JVM shutdown hook，会在进程退出时再做一次 close()
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            int idx = i * 2;
            out[i] = (byte) Integer.parseInt(hex.substring(idx, idx + 2), 16);
        }
        return out;
    }
}
