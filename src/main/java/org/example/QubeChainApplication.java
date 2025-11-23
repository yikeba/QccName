package org.example;   // 你现在的包名保持不变

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.example.config.QubePath;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import org.springframework.scheduling.annotation.EnableScheduling;   // 这行必须加！开启定时任务

import java.security.Security;

// 这三个注解是核心！缺一不可
@SpringBootApplication        // 告诉IntelliJ这是SpringBoot主类
@EnableScheduling             // 开启10分钟切容器定时器
public class QubeChainApplication {

    // 【关键修改：使用静态块确保最早注册】
    static {
        // 尝试注册 BouncyCastleProvider
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            System.out.println(">>> [Static Init] BouncyCastle Provider 已全局注册。");
        }
        // 注意：请确认您使用的是 BouncyCastleProvider.PROVIDER_NAME
        // 或者直接使用 "BC" 字符串，但 BouncyCastleProvider.PROVIDER_NAME 更安全。
    }

    public static void main(String[] args) {
        QubePath.init(); // 就这一行！！！所有路径搞定！！！
        SpringApplication.run(QubeChainApplication.class, args);

        System.out.println("╔══════════════════════════════════════╗");
        System.out.println("║    QubeChain ∞ 全球最硬容器链已启动    ║");
        System.out.println("║  10分钟切容器 | 树状无限扩散 | 抗量子   ║");
        System.out.println("║   3台服务器准备就绪，fChat上链开始！   ║");
        System.out.println("╚══════════════════════════════════════╝");
    }
}