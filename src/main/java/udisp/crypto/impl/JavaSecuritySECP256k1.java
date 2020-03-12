package udisp.crypto.impl;

import udisp.crypto.Signer;
import udisp.crypto.Verifier;
import udisp.crypto.utils.Utils;
import udisp.entity.SignedDocument;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


// https://metamug.com/article/security/sign-verify-digital-signature-ecdsa-java.html
public class JavaSecuritySECP256k1 implements Signer, Verifier {

    public SignedDocument signSomething() throws Exception {

        String messageToSign = "something_to_sign";
        // prepare keypair secp256k1
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(ecSpec, new SecureRandom());

        KeyPair keypair = generator.generateKeyPair();
        PrivateKey privateKey = keypair.getPrivate();
        System.out.println(privateKey.getEncoded().length);
        PublicKey publicKey = keypair.getPublic();
//        System.out.println(Utils.compressPubKey(new BigInteger(1, keypair.getPublic().getEncoded())).getBytes().length);

        // signSomething
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA"); // NONEwithECDSA
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(messageToSign.getBytes());
        byte[] signature = ecdsaSign.sign();

        String pubKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());

        // signed data for verifier
        return new SignedDocument(pubKey, Utils.extractR(signature), Utils.extractS(signature), messageToSign);
    }

    public boolean verify(SignedDocument signedDocument) throws Exception {
        byte[] pubKey = Base64.getDecoder().decode(signedDocument.getPublicKey());
        byte[] originalMessage = signedDocument.getOriginalDocument().getBytes();

        PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(pubKey));

        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(originalMessage);

        byte[] signature = Utils.fromECDSAtoASN1(signedDocument.getR(), signedDocument.getS());

        return ecdsaVerify.verify(signature);
    }

}
