package domain;

import java.security.PrivateKey;

public interface SecuredMessage {
    byte[] decrypt(PrivateKey privateKey);
    byte[] getSign();
    Certificate getCertificate();
    String getSignAlg();
}
