package domain;

import javax.crypto.KeyGenerator;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;

public interface CryptoFactory {
    SignatureManager createSignatureManager();
    User createUser(String name);
    KeyPairGenerator createKeyPairGenerator();
    KeyGenerator createKeyGenerator();
    CertificationCenter getCertificationCenter();
    String getSignAlg();
    AlgorithmParameterSpec getSignProperties();
    String getSymmetricAlg();
    String getAsymmetricAlg();
    String getKeyGenAlg();
}
