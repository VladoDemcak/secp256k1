package udisp.crypto.impl;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Base64;

import udisp.crypto.Signer;
import udisp.crypto.Verifier;
import udisp.crypto.utils.Utils;
import udisp.entity.SignedDocument;

// only Bouncy castle dependencies
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

// https://github.com/trevorbernard/cosigner/blob/master/cosigner-common/src/main/java/io/emax/cosigner/common/crypto/Secp256k1.java
public class BouncyCastleSECP256k1 implements Signer, Verifier {


    @Override
    public SignedDocument signSomething() throws NoSuchAlgorithmException {

        BigInteger privateKey = new BigInteger("87ddae0f3a25b92268175400149d65d6887b9cefaf28ea2c078e05cdc15a3c0a", 16);

        // generate public key from private key with secp256k1
        Security.addProvider(new BouncyCastleProvider());
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPoint pointQ = spec.getG().multiply(privateKey).normalize();
        byte[] encoded = pointQ.getEncoded(false);
        BigInteger publicKey = new BigInteger(1, Utils.removePrefix(encoded));

        // sign something
        String messageToSign = "something_to_sign";
        ECDomainParameters domain = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN());
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, new ECPrivateKeyParameters(privateKey, domain));
        MessageDigest digest = MessageDigest.getInstance("Keccak-256");
        byte[] hash = digest.digest(messageToSign.getBytes(StandardCharsets.UTF_8));
        BigInteger[] signature = signer.generateSignature(hash);

        // prepare result
        String pubKeyHex = publicKey.toString(16);
        byte[] r = signature[0].toByteArray();
        byte[] s = signature[1].toByteArray();
        String signedDocument = Base64.getEncoder().encodeToString(hash);
        return new SignedDocument(pubKeyHex, r, s, signedDocument);
    }

    @Override
    public boolean verify(SignedDocument signedDocument) {

        BigInteger publicKey = new BigInteger(Utils.cleanHexPrefix(signedDocument.getPublicKey()), 16);
        byte[] signedMessage = Base64.getDecoder().decode(signedDocument.getOriginalDocument());

        Security.addProvider(new BouncyCastleProvider());
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECDomainParameters domain = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN());
        // public key as ECPoint mandatory for ECDSASigner verifySignature
        ECPoint G = spec.getCurve().decodePoint(Hex.decode("04" + publicKey.toString(16))); // 04 means uncompressed key

        ECDSASigner signer = new ECDSASigner();
        signer.init(false, new ECPublicKeyParameters(G, domain));
        BigInteger r = new BigInteger(1, signedDocument.getR());
        BigInteger s = new BigInteger(1, signedDocument.getS());
        return signer.verifySignature(signedMessage, r, s);
    }

}
