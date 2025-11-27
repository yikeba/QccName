package org.que.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.security.Security;

public class DemoTest {

    // 【关键修复：静态块注册】确保在 main() 执行之前，BCProvider 就位
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            System.out.println(">>> [DemoTest Static Init] BouncyCastle Provider 强制注册成功！");
        }
    }

    public static void main(String[] args) {
        System.out.println("QubeChain ∞ 抗量子签名全流程演示开始！\n");

        // 1. 生成钱包
        QubeKeyGenerator.Wallet wallet = QubeKeyGenerator.generateWallet();

        // 2. 模拟fChat销售交易
        String tx = "SALES|merchant:888|amount:88888.88|time:2025-11-22,sdfsdfsdfsdfsdfdfgdfgdgddfg";

        // 3. 签名
        //String signature = QubeSigner.sign(tx,wallet.privateKeyParameters);
        String signature = QubeSigner.sign(tx,wallet.privateKeyHex);
        // 4. 验证
        //boolean valid = QubeSigner.verify(tx, signature, wallet.publicKeyHex);
        boolean valid = QubeSigner.verifyRaw(tx.getBytes(),  Hex.decode(signature), wallet.publicKeyHex);
        System.out.println("\n交易内容: " + tx);
       // System.out.println("签名: " + signature+"签名长度："+signature.length());
        System.out.println("byte[]验证结果: " + (valid ? "成功！！！量子计算机也改不了！！！" : "失败"));
      //  System.out.println("字符串验证结果: " + (validstr ? "成功！！！量子计算机也改不了！！！" : "失败"));
        System.out.println("\nQubeChain ∞ 抗量子签名系统已就绪！全球最硬！！！");
    }
}