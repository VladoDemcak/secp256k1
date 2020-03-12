package udisp.entity;

import java.math.BigInteger;

public final class SignedDocument {

    private String publicKey; // in hex format
    private String originalDocument; // base64 encoded byte[]

    // signature itself
    private byte[] r;
    private byte[] s;

    public SignedDocument(String publicKey, byte[] r, byte[] s, String originalDocument) {
        this.originalDocument = originalDocument;
        this.publicKey = publicKey;
        this.r = r;
        this.s = s;
    }

    public byte[] getR() {
        return r;
    }

    public byte[] getS() {
        return s;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getOriginalDocument() {
        return originalDocument;
    }

    @Override
    public String toString() {
        return "{"
                + "\"publicKey\":\"" + publicKey + "\""
                + ",\"originalDocument\":\"" + originalDocument + "\""
                + ",\"r\":" + new BigInteger(1, r)
                + ",\"s\":" + new BigInteger(1, s)
                + "}";
    }
}
