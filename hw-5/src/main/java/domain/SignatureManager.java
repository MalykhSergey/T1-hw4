package domain;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

public interface SignatureManager {
    byte[] sign(byte[] data);

    boolean verify(byte[] data, byte[] sign, PublicKey verifyKey);

    <T> boolean verify(byte[] data, byte[] sign, PublicKey verifyKey, SignedMessage<T> signedMessage);

    void setSignKey(PrivateKey privateKey);

    AlgorithmParameterSpec getParameters();

    String getSignAlg();
}
