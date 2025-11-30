package org.que.wallet;


import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;

public class WalletSigner {

    //===============================
    //   String 消息 → HEX 签名
    //===============================
    public static String sign(String msg, DilithiumPrivateKeyParameters priv) {
        return sign(msg.getBytes(StandardCharsets.UTF_8), priv);
    }

    //===============================
    //   byte[] 消息 → HEX 签名
    //===============================
    public static String sign(byte[] msgBytes, DilithiumPrivateKeyParameters priv) {
        DilithiumSigner signer = new DilithiumSigner();
        signer.init(true, priv);
        byte[] sig = signer.generateSignature(msgBytes);
        return Hex.toHexString(sig);
    }

    //===============================
    //   String 消息 + 签名(HEX) 验证
    //===============================
    public static boolean verify(String msg, String sigHex, DilithiumPublicKeyParameters pub) {
        return verify(msg.getBytes(StandardCharsets.UTF_8), Hex.decode(sigHex), pub);
    }

    //===============================
    //   byte[] 消息 + 签名(byte) 验证
    //===============================
    public static boolean verify(byte[] msgBytes, byte[] sigBytes, DilithiumPublicKeyParameters pub) {
        DilithiumSigner verifier = new DilithiumSigner();
        verifier.init(false, pub);
        return verifier.verifySignature(msgBytes, sigBytes);
    }
}
