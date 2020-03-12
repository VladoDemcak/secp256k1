package udisp.crypto.impl;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.web3j.crypto.*;
import org.web3j.utils.Numeric;
import udisp.crypto.Signer;
import udisp.crypto.Verifier;
import udisp.crypto.utils.Utils;
import udisp.entity.SignedDocument;

import java.math.BigInteger;
import java.security.Security;
import java.security.SignatureException;
import java.util.Base64;

public class Web3jSECP256k1 implements Signer, Verifier {


    @Override
    public SignedDocument signSomething() {

        BigInteger privateKey = new BigInteger("87ddae0f3a25b92268175400149d65d6887b9cefaf28ea2c078e05cdc15a3c0a", 16);

        // generate public key from private key with secp256k1
        Security.addProvider(new BouncyCastleProvider());
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPoint pointQ = spec.getG().multiply(privateKey).normalize();
        byte[] encoded = pointQ.getEncoded(false);
        BigInteger publicKey = new BigInteger(1, Utils.removePrefix(encoded));

        // prepare credentials for web3 transaction sign
        ECKeyPair keyPair = new ECKeyPair(privateKey, publicKey);
        Credentials credentials = Credentials.create(keyPair);

        // sign something
        RawTransaction rawTransaction = Utils.randomEtherTransaction();
        byte[] signedTransaction = TransactionEncoder.signMessage(rawTransaction, credentials);

        // decode RLP signed Transaction b/c we need to get R,S and signed data
        SignedRawTransaction result = (SignedRawTransaction) TransactionDecoder.decode(Numeric.toHexString(signedTransaction));

        // prepare result
        String pubKeyHex = publicKey.toString(16);
        byte[] r = result.getSignatureData().getR();
        byte[] s = result.getSignatureData().getS();

        // Web3js Sign.signMessage uses Hash.sha3 https://github.com/web3j/web3j/blob/c0b7b9c2769a466215d416696021aa75127c2ff1/crypto/src/main/java/org/web3j/crypto/Sign.java#L74-L81
        String signedDocument = Base64.getEncoder().encodeToString(Hash.sha3(TransactionEncoder.encode(result)));
        return new SignedDocument(pubKeyHex, r, s, signedDocument);
    }

    @Override
    public boolean verify(SignedDocument signedDocument) {

        byte[] signedMessage = Base64.getDecoder().decode(signedDocument.getOriginalDocument());

        // decode RLP signed Transaction b/c we need to get R,S and signed data
        SignedRawTransaction result = (SignedRawTransaction) TransactionDecoder.decode(Numeric.toHexString(signedMessage));

        String fromAddress = "0x0b20cfccee73b1803d1fa7e00f9f859b980abca5";
        try {
            // web3j does verification with comparing fromAddress
            result.verify(fromAddress);
            System.out.println("valid!!!");
            return true;
        } catch (SignatureException e) {
            System.out.println("not valid");
            return false;
        }
    }

}