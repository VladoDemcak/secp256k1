package udisp.crypto;

import udisp.entity.SignedDocument;

public interface Verifier {

    boolean verify(SignedDocument signedDocument) throws Exception;
}
