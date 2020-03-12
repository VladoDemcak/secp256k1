package udisp.crypto.utils;


import org.bouncycastle.asn1.*;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.Sign;
import org.web3j.utils.Strings;
import udisp.entity.SignedDocument;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.function.Predicate;

public class Utils {

    // Notes
    // There are a few standard representations/encodings of an ECDSA (or DSA) signature. The one Java JCE uses is an ASN.1 DER encoding
    // RFC3279 2.2.3 ECDSA Signature Algorithm When signing, the ECDSA algorithm generates two values.  These values are commonly referred to as r and s.  To easily transfer these two values as one signature, they MUST be ASN.1 encoded using the following ASN.1 structure:
    //


    public static void findPublicKey(SignedDocument signedDocument) {
        ECDSASignature ecdsaSignature = new ECDSASignature(new BigInteger(1, signedDocument.getR()), new BigInteger(1, signedDocument.getS()));

        byte[] signedMessage = Base64.getDecoder().decode(signedDocument.getOriginalDocument());
        // The recId is an index from 0 to 3 which indicates which of the 4 possible keys is the
        // correct one. Because the key recovery operation yields multiple potential keys, the correct
        // key must either be stored alongside the signature, or you must be willing to try each recId
        // in turn until you find one that outputs the key you are expecting.
        // https://github.com/web3j/web3j/blob/c65e6bebf52fd3e897056b0ffb8dac01153668f1/crypto/src/main/java/org/web3j/crypto/Sign.java#L84-L92
        for (int i = 0; i < 4; i++) {
            // An ECKey containing only the public part, or null if recovery wasn't possible.
            BigInteger ecPublicPartKey = Sign.recoverFromSignature(i, ecdsaSignature, signedMessage);

            if (!Objects.isNull(ecPublicPartKey) && publicKeyMatches(signedDocument, ecPublicPartKey)) {
                System.out.println(String.format("Public has been found! recId '%d' yields: '%s'", i, ecPublicPartKey.toString(16)));
            } else if (!Objects.isNull(ecPublicPartKey)) {
                System.out.println(String.format("recId '%d' is not correct b/c key is: '%s'", i, ecPublicPartKey.toString(16)));
            } else {
                System.out.println(String.format("recId '%d' is not correct", i));
            }
        }
    }

    private static boolean publicKeyMatches(SignedDocument signedDocument, BigInteger ecPublicPartKey) {
        return ecPublicPartKey.toString(16).equals(signedDocument.getPublicKey());
    }

    public static byte[] extractR(byte[] asn1Sig) throws IOException {
        ASN1InputStream asn1 = new ASN1InputStream(asn1Sig);
        DLSequence seq = (DLSequence) asn1.readObject();
//        return ((ASN1Integer) seq.getObjectAt(0)).getPositiveValue();
        return ((ASN1Integer) seq.getObjectAt(0)).getPositiveValue().toByteArray();
    }

    public static byte[] extractS(byte[] asn1Sig) throws IOException {
        ASN1InputStream asn1 = new ASN1InputStream(asn1Sig);
        DLSequence seq = (DLSequence) asn1.readObject();
        return ((ASN1Integer) seq.getObjectAt(1)).getPositiveValue().toByteArray();
    }

    public static byte[] fromECDSAtoASN1(byte[] r, byte[] s) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DEROutputStream derOutputStream = new DEROutputStream(byteArrayOutputStream);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        derOutputStream.writeObject(new DERSequence(v));
        return byteArrayOutputStream.toByteArray(); // derSignature
    }

    public static BigInteger compressPubKey(BigInteger pubKey) {
        String pubKeyYPrefix = pubKey.testBit(0) ? "03" : "02";
        String pubKeyHex = pubKey.toString(16);
        String pubKeyX = pubKeyHex.substring(0, 64);
        return new BigInteger(pubKeyYPrefix + pubKeyX, 16);
    }

    public static RawTransaction randomEtherTransaction() {
        return RawTransaction.createEtherTransaction(
                new BigInteger(1, "0".getBytes()),
                new BigInteger(1, "0".getBytes()),
                new BigInteger(1, "0".getBytes()),
                "0",
                new BigInteger(1, "0".getBytes()));
    }


    public static String cleanHexPrefix(String input) {

        Predicate<String> containsHexPrefix = (i) -> !Strings.isEmpty(i)
                && i.length() > 1
                && i.charAt(0) == '0'
                && i.charAt(1) == 'x';

        if (containsHexPrefix.test(input)) {
            return input.substring(2);
        } else {
            return input;
        }
    }

    public static byte[] removePrefix(byte[] encoded) {
        return Arrays.copyOfRange(encoded, 1, encoded.length);
    }

}
