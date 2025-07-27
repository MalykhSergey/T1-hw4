package infrastructure;

import domain.*;

import javax.crypto.KeyGenerator;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class CryptoFactoryImpl implements CryptoFactory {

    private final String SIGN_ALG;
    private final AlgorithmParameterSpec SIGN_PROPERTIES;
    private final String KEY_GEN_ALG;
    private final String ASYMMETRIC_ALG;
    private final String SYMMETRIC_ALG;
    private final CertificationCenterImpl certificationCenter;
    private final String KEY_PAIR_GEN_ALG;
    private final int KEY_SIZE;

    public CryptoFactoryImpl(CertificateRepository certificateRepository, KeyPair keyPair, String SIGN_ALG, AlgorithmParameterSpec SIGN_PROPERTIES, String KEY_GEN_ALG, String KEY_PAIR_GEN_ALG, int KEY_SIZE, String ASYMMETRIC_ALG, String SYMMETRIC_ALG) {
        this.SIGN_ALG = SIGN_ALG;
        this.SIGN_PROPERTIES = SIGN_PROPERTIES;
        this.KEY_GEN_ALG = KEY_GEN_ALG;
        this.ASYMMETRIC_ALG = ASYMMETRIC_ALG;
        this.SYMMETRIC_ALG = SYMMETRIC_ALG;
        this.KEY_PAIR_GEN_ALG = KEY_PAIR_GEN_ALG;
        this.KEY_SIZE = KEY_SIZE;
        try {
            KeyPairGenerator keyPairGenerator;
            if (keyPair == null) {
                keyPairGenerator = createKeyPairGenerator();
            } else {
                keyPairGenerator = new KeyPairGenerator(KEY_PAIR_GEN_ALG) {
                    @Override
                    public KeyPair generateKeyPair() {
                        return keyPair;
                    }
                };
            }
            certificationCenter = new CertificationCenterImpl("AuthService", certificateRepository, createSignatureManager(), keyPairGenerator);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public CryptoFactoryImpl(CertificateRepository certificateRepository, KeyPair keyPair) {
        this(certificateRepository, keyPair, "RSASSA-PSS", new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1
        ),"AES", "RSA", 2048, "RSA/ECB/OAEPWithSHA-256AndMGF1Padding","AES/CBC/PKCS5Padding");
    }

    @Override
    public SignatureManager createSignatureManager() {
        return new SignatureManagerImpl(SIGN_ALG, SIGN_PROPERTIES);
    }

    @Override
    public User createUser(String name) {
        return new CryptoUser(name, certificationCenter, createKeyPairGenerator(), createSignatureManager(), SIGN_ALG, SIGN_PROPERTIES, KEY_GEN_ALG, ASYMMETRIC_ALG, SYMMETRIC_ALG);
    }

    @Override
    public KeyPairGenerator createKeyPairGenerator() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_PAIR_GEN_ALG);
            keyGen.initialize(KEY_SIZE);
            return keyGen;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public KeyGenerator createKeyGenerator() {
        try {
            return KeyGenerator.getInstance(KEY_GEN_ALG);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public CertificationCenter getCertificationCenter() {
        return certificationCenter;
    }

    @Override
    public String getSignAlg() {
        return SIGN_ALG;
    }

    @Override
    public AlgorithmParameterSpec getSignProperties() {
        return SIGN_PROPERTIES;
    }

    @Override
    public String getSymmetricAlg() {
        return SYMMETRIC_ALG;
    }

    @Override
    public String getAsymmetricAlg() {
        return ASYMMETRIC_ALG;
    }

    @Override
    public String getKeyGenAlg() {
        return KEY_GEN_ALG;
    }
}
