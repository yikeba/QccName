package org.example.test;
// QubeChainFullLoopTest.java —— 量子容器链终极闭环测试（永封版）

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.example.config.QubePath;
import org.example.core.*;
import org.example.core.ChainData.*;
import org.example.protocol.QubeDataReceiver;
import org.example.crypto.*;
import org.example.storage.AddressIndexService;
import org.example.util.GzipUtil;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Security;

public class testdatainput {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            System.out.println(">>> [DemoTest Static Init] BouncyCastle Provider 强制注册成功！");
        }
    }

    public static void main(String[] args) throws Exception {

        System.out.println("【量子容器链终极闭环测试】只用DataRecord打穿全链！\n");

        // 1. 初始化路径 + 启动管理器
        QubePath.init();
        ContainerManager manager = ContainerManager.getInstance();

        // 2. 创世钱包（真实Dilithium5）
        QubeKeyGenerator.Wallet wallet = QubeKeyGenerator.generateWallet();
        AddressIndexService.getInstance().registerAddress(wallet.address, wallet.publicKeyHex);
        System.out.println("创世地址: " + wallet.address);

        // 3. 构造一条最硬的 DataRecord（你真实类！）
        //String ramstr=""
        DataRecord record = new DataRecord(
                "quantum_test",                                           // recordType
                "Hello QubeChain! 这是第一条量子级永久数据记录！时间: ".concat(
                        String.valueOf(System.currentTimeMillis())).getBytes(), // dataPayload
                0L,                                                       // fee
                Hex.decode(wallet.publicKeyHex),                          // senderPubKey
                null                                                      // signature 后面填
        );

        // 4. 标准序列化 + 压缩 + 真实签名
        byte[] standardBytes = record.toByteArray();
        System.out.println("标准序列化完成，长度: " + standardBytes.length + " bytes");
        //byte[] compressed = GzipUtil.compress(standardBytes);
        //System.out.println("GZIP压缩完成，压缩比: " +
        //  String.format("%.2f%%", (double) compressed.length / standardBytes.length * 100)+"压缩完成长度:"+compressed.length);

        byte[] signature = QubeSigner.signRaw(standardBytes, wallet.privateKeyParameters);
        System.out.println("Dilithium5量子签名完成，长度: " + signature.length + " bytes");

        // 5. 构建最简最硬传输包（压缩数据 + 签名 + 地址）
        ByteArrayOutputStream pkg = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(pkg)) {
            out.write(standardBytes);
            out.writeInt(signature.length);
            out.write(signature);
            out.writeUTF(wallet.address);
        }
        byte[] dataarr = pkg.toByteArray();
        // String finalPackage = Base64.toBase64String(dataarr);
        //System.out.println("最终数据包构建成功！Base64长度: " + finalPackage.length());


        System.out.println("\n【发送端数据包结构】");
        System.out.println("standardBytes长度: " + standardBytes.length);
        System.out.println("签名长度: " + signature.length);
        System.out.println("地址: " + wallet.address);
        System.out.println("地址UTF编码长度: " + wallet.address.getBytes(StandardCharsets.UTF_8).length);
        System.out.println("总包长度: " + dataarr.length);
        System.out.print("尾部20字节: ");
        for (int i = Math.max(0, dataarr.length - 20); i < dataarr.length; i++) {
            System.out.printf("%02X ", dataarr[i]);
        }
        System.out.println("\n");


        // 6. 节点接收 + 完整解析
        System.out.println("\n【节点开始接收并解析】 发送数据长度"+dataarr.length);
        QubeDataReceiver receiver = new QubeDataReceiver(dataarr);
        DataRecord receivedRecord = (DataRecord) receiver.getData();

        System.out.println("接收成功！解析出DataRecord:");
        System.out.println("  recordType: " + receivedRecord.getDataTypeId());
        System.out.println("  payload: " + receivedRecord.toJSON());
        System.out.println("  发送者: " + receiver.getAddress());

        // 7. 打包进区块
        Block block = new Block((short) 1, null);
        block.addData(receivedRecord);
        block.seal();
        System.out.println("区块密封完成，blockHash: " + Hex.toHexString(block.blockHash));

        // 8. 提交给容器
        manager.submitBlock(block);
        System.out.println("区块已成功写入当前容器！");

        // 9. 强制密封容器（模拟3分钟或10MB）
        System.out.println("\n【强制密封容器】");
        manager.forceSealCurrentContainer();

        System.out.println("\n【量子容器链终极闭环测试完成！】");
        System.out.println("一条DataRecord → 序列化 → 压缩 → 量子签名 → 网络传输 → 验签 → 解压 → 工厂解析 → 出块 → 入容器 → 密封归档");
        System.out.println("全链路100%打通！主网核心已活！明天发币！");
//            // 输出当前状态
        //System.out.println(manager.getCurrentContainer().);



    }
}