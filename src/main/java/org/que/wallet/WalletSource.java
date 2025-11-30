package org.que.wallet;

import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;

public class WalletSource {
    public final String address;       // Q开头Base58地址
    public final String privateKeyHex;
    public final String publicKeyHex;
    public final DilithiumPrivateKeyParameters privateKeyParameters;
    WalletSource(String address, String privateKey, String publicKey,DilithiumPrivateKeyParameters privateKeyParameters) {
        this.address = address;
        this.privateKeyHex = privateKey;
        this.publicKeyHex = publicKey;
        this.privateKeyParameters=privateKeyParameters;

    }


    //================ 签名 =================
    public static String sign(String msg, DilithiumPrivateKeyParameters priv) {
        DilithiumSigner signer = new DilithiumSigner();
        signer.init(true, priv);
        byte[] sig = signer.generateSignature(msg.getBytes(StandardCharsets.UTF_8));
        return Hex.toHexString(sig);
    }

    //================ 验签 =================
    public static boolean verify(String msg, String sigHex, DilithiumPublicKeyParameters pub) {
        DilithiumSigner verifier = new DilithiumSigner();
        verifier.init(false, pub);
        return verifier.verifySignature(
                msg.getBytes(StandardCharsets.UTF_8),
                Hex.decode(sigHex)
        );
    }



}