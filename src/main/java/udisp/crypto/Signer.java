package udisp.crypto;

import udisp.entity.SignedDocument;

public interface Signer {

    SignedDocument signSomething() throws Exception;
}
