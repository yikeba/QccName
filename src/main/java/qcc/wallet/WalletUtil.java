package qcc.qccwallet;

import org.bouncycastle.pqc.crypto.mldsa.*;
import org.bouncycastle.util.encoders.Hex;
import java.security.SecureRandom;

/**
 * ════════════════════════════════════════════════════════
 * 修复说明：
 *   原版本这里自己复制了一份 createAddress()/calculateChecksum()，
 *   并且自带一个独立的 QCC_VERSION_BYTE = 0x00 常量，与
 *   AddressTool.creatAddress() 里的常量各自为政。
 *   这是个真实的双重实现风险：AddressTool 是服务端验证客户端
 *   地址、以及 QccMnemonicWallet 助记词恢复钱包所用的权威实现；
 *   如果只改这边的常量而不改 AddressTool，会导致"随机生成的
 *   钱包"和"助记词恢复的钱包"用不同 version byte 生成地址，
 *   两者互相校验失败。
 *   修复方式：删除本类里的重复逻辑，统一调用
 *   AddressTool.creatAddress()，让地址生成永远只有一份权威实现。
 * ════════════════════════════════════════════════════════
 */
public class WalletUtil {
    private static final SecureRandom random = new SecureRandom();

    public static QccWallet createWallet() {
        // 1. 初始化 ML-DSA-87 生成器
        MLDSAKeyPairGenerator generator = new MLDSAKeyPairGenerator();
        generator.init(new MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_87));

        // 2. 生成密钥对
        var kp = generator.generateKeyPair();
        MLDSAPublicKeyParameters pubKey = (MLDSAPublicKeyParameters) kp.getPublic();
        MLDSAPrivateKeyParameters privKey = (MLDSAPrivateKeyParameters) kp.getPrivate();

        // 3. 编码为 Hex
        // ML-DSA-87 标准：私钥 4896 字节, 公钥 2592 字节 (原始编码)
        String privHex = Hex.toHexString(privKey.getEncoded());
        String pubHex = Hex.toHexString(pubKey.getEncoded());

        // 4. 生成 Q 开头的地址 —— 统一调用 AddressTool，不再自己重复实现
        String address = AddressTool.creatAddress(pubHex);

       // LogObj.println("ML-DSA-87 抗量子钱包生成成功！");
      //  LogObj.println("地址: " + address);
     //   LogObj.println("公钥长度: " + pubKey.getEncoded().length + " 字节");
     //   LogObj.println("私钥长度: " + privKey.getEncoded().length + " 字节");

        return new QccWallet(address, privHex, pubHex);
    }
}
