import org.junit.Assert;
import org.junit.Test;
import udisp.crypto.Signer;
import udisp.crypto.impl.BouncyCastleSECP256k1;
import udisp.crypto.impl.JavaSecuritySECP256k1;
import udisp.crypto.impl.Web3jSECP256k1;
import udisp.crypto.utils.Utils;
import udisp.entity.SignedDocument;

import java.math.BigInteger;

public class SignVerifyTest {

    @Test
    public void signedWithBouncycastleAndVerifyWithBouncycastle() throws Exception {

        Signer signer = new BouncyCastleSECP256k1();
        SignedDocument signedDocument = signer.signSomething();
        System.out.println(signedDocument);

        Utils.findPublicKey(signedDocument);
        boolean result = new BouncyCastleSECP256k1().verify(signedDocument);
        // assert statements
        Assert.assertTrue("Signed with Bouncycastle has to be verified by Bouncycastle", result);
    }

    @Test
    public void signedWithWeb3jHasToBeVerifiedWithBouncycastle() throws Exception {

        Signer signer = new Web3jSECP256k1();
        SignedDocument signedDocument = signer.signSomething();
        System.out.println(signedDocument);
        Utils.findPublicKey(signedDocument);

        boolean result = new BouncyCastleSECP256k1().verify(signedDocument);
        // assert statements
        Assert.assertTrue("Signed with web3j has to be verified by Bouncycastle", result);
    }

// Doesnt work
//    @Test
//    public void signedWithBouncycastleVerifiedWithJava() throws Exception {
//
//        Signer signer = new BouncyCastleSECP256k1();
//        SignedDocument signedDocument = signer.signSomething();
//        System.out.println(signedDocument);
//        Utils.findPublicKey(signedDocument);
//
//        boolean result = new JavaSecuritySECP256k1().verify(signedDocument);
//        // assert statements
//        Assert.assertTrue("Signed with BouncyCastleSECP256k1 has to be verified with JavaSecuritySECP256k1", result);
//    }


    @Test
    public void signedWithJavaVerifiedWithJava() throws Exception {

        SignedDocument signedDocument = new JavaSecuritySECP256k1().signSomething();
        BigInteger r = new BigInteger(1, signedDocument.getR());
        BigInteger s = new BigInteger(1,signedDocument.getS());
        System.out.println("r: " + r);
        System.out.println("s: " + s);
        System.out.println("pubkey: " + signedDocument.getPublicKey());

        boolean result = new JavaSecuritySECP256k1().verify(signedDocument);
        System.out.println(String.format("Valid signature: %s", result));
        // assert statements
        Assert.assertTrue("Signed with java has to be verified with java", result);
    }

}
