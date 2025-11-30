package org.que.protocol;

import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.que.core.queBlock.BlockController;
import org.que.core.queData.QubeDataBaseFactory;
import org.que.core.queData.QueBaseData;
import org.que.wallet.QubeWallet;

public class QubePacketHandler {

    /**
     * 通讯层处理流程：
     * 1. 解析 DER 公钥
     * 2. 验证签名
     * 3. 派生 address
     * 4. 填充 data.from
     * 5. 将 data 送入区块队列
     */
    public static String handle(QubePacket packet) {
        try {
            // 1. 解析 DER 公钥
            byte[] pubBytes = Hex.decode(packet.publicKey);
            DilithiumPublicKeyParameters pubObj =
                    new DilithiumPublicKeyParameters(pubBytes);

            // 2. 验证签名（payloadJson 本身就是签名字符串）
            boolean ok = QubeWallet.verify(
                    packet.payloadJson,
                    packet.signature,
                    pubObj
            );

            if (!ok) {
                return "{ \"status\": \"error\", \"message\": \"invalid signature\" }";
            }

            // 3. 解析 payload → 三大数据对象
            QueBaseData data = QubeDataBaseFactory.fromJson(packet.payloadJson);

            // 4. 由公钥生成 address
            byte[] rawPk = QubeWallet.getRawPublicKey(pubObj);
            String address = QubeWallet.generateAddress(rawPk);

            // 5. 三大数据对象写入 from 字段（强制覆盖客户端的 from）
            data.from = address;

            // 6. 手续费（测试网=0）
            data.fee = 0L;

            // 7. 送入区块管理器
            BlockController.receive(data);

            int q = BlockController.getQueueSize();
            return "{ \"status\": \"accepted\", " +
                    "\"dataId\": \"" + data.id + "\"," +
                    "\"queueSize\": " + q + " }";

        } catch (Exception e) {
            e.printStackTrace();
            return "{ \"status\": \"error\", \"message\": \"internal error\" }";
        }
    }
}
