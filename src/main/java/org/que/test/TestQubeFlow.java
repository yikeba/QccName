package org.que.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.que.core.queData.EntityData;
import org.que.core.queData.QueBaseData;
import org.que.core.queData.TransactionData;
import org.que.wallet.QubeWallet;
import org.que.wallet.QubeWallet.Wallet;
import org.que.protocol.QubeDataProtocol;
import org.que.protocol.QubePacket;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

public class TestQubeFlow {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            System.out.println(">>> [DemoTest Static Init] BouncyCastle Provider 强制注册成功！");
        }
    }


    public static void main(String[] args) throws Exception {

        // 1. 模拟一个钱包（客户端身份）
        Wallet wallet = QubeWallet.QubeWallet();
        DilithiumPrivateKeyParameters privKey = wallet.privateKeyParameters;
        byte[] pubKeyBytes = hexToBytes(wallet.publicKeyHex);

        String contractAddress = "QCONTRACT_DEMO_001";

        // 2. 模拟客户端构建几条数据（交易 + 实体）
        List<QueBaseData> dataList = new ArrayList<>();

        // 2.1 一条交易
        TransactionData tx = new TransactionData(contractAddress);
        tx.from = wallet.address;
        tx.to = "Q_RECEIVER_001";
        tx.amount = 12345; // 123.45
        tx.memo = "测试交易";
        tx.publicKey = wallet.publicKeyHex;
        tx.sign(privKey);
        dataList.add(tx);

        // 2.2 一条实体
        EntityData entity = new EntityData(contractAddress);
        entity.owner = wallet.address;
        entity.content = "{\"name\":\"demo\",\"value\":1}";
        entity.publicKey = wallet.publicKeyHex;
        entity.sign(privKey);
        dataList.add(entity);

        // 3. 客户端：逐条打包成 QubePacket（模拟发送）
        List<byte[]> networkBytes = new ArrayList<>();
        for (QueBaseData data : dataList) {
            QubePacket packet = QubeDataProtocol.encodeData(data, privKey, pubKeyBytes);
            networkBytes.add(packet.toBytes()); // 这里模拟“网络发送的字节”
        }

        // 4. 服务器：接收字节 → 解析 QubePacket → 还原 QueBaseData
        List<QueBaseData> receivedDataList = new ArrayList<>();
        for (byte[] bytes : networkBytes) {
            QubePacket packet = QubePacket.parse(bytes);      // 解析协议
            QueBaseData data = QubeDataProtocol.decodeData(packet); // 验签 + 还原数据
            receivedDataList.add(data);
            System.out.println("服务端收到数据: " + data);
        }

        // 5. 这里你就可以把 receivedDataList 丢进 QueBlockBody / QueBaseBlock / 容器了
        //    例如：
        //
        // QueBlockBody body = new QueBlockBody();
        // body.dataList = receivedDataList;
        // QueBlockHead head = ... // 填 blockNumber / containerId / timestamp 等
        // QueBlockFoot foot = ... // 计算 dataListHash / blockHash
        // QueBaseBlock block = new QueBaseBlock(head, body, foot);
        //
        // 然后把多个 block → QueContainerWriter.writeContainer(...)
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
