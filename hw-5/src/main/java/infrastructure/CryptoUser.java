package infrastructure;

import domain.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.time.Instant;

public class CryptoUser implements User {
    private final KeyPair keyPair;
    private final SignatureManager signatureManager;
    private final String name;
    private final Certificate certificate;

    public final String SIGN_ALG;
    private final AlgorithmParameterSpec SIGN_PROPERTIES;
    public final String KEY_GEN_ALG;
    public final String ASYMMETRIC_ALG;
    public final String SYMMETRIC_ALG;
    private final CertificationCenter certificationCenter;
    private final Certificate generalCertificate;

    CryptoUser(
            String name,
            CertificationCenter certificationCenter,
            KeyPairGenerator keyGen,
            SignatureManager signatureManager,
            String signAlg, AlgorithmParameterSpec signProperties,
            String keyGenAlg,
            String asymmetricAlg,
            String symmetricAlg
    ) {
        SIGN_ALG = signAlg;
        SIGN_PROPERTIES = signProperties;
        KEY_GEN_ALG = keyGenAlg;
        ASYMMETRIC_ALG = asymmetricAlg;
        SYMMETRIC_ALG = symmetricAlg;
        this.name = name;
        this.signatureManager = signatureManager;
        this.keyPair = keyGen.generateKeyPair();
        this.certificationCenter = certificationCenter;
        this.generalCertificate = certificationCenter.getCertificate(certificationCenter.getName());
        certificate = certificationCenter.issueCertificate(name, keyPair.getPublic());
        signatureManager.setSignKey(keyPair.getPrivate());
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public SecuredMessage sendSecuredMessage(PublicKey receiverKey, byte[] data) {
        return new CipherMessage(certificate, receiverKey, data, signatureManager.sign(data), SIGN_ALG, SIGN_PROPERTIES, KEY_GEN_ALG, ASYMMETRIC_ALG, SYMMETRIC_ALG);
    }

    @Override
    public void receiveMessage(SecuredMessage securedMessage) {
        // Запрос проверки подлинности сертификата по незащищённому каналу
        // Центр сертификации отвечает в формате подписанных сообщений (информация несекретная)
        // Изменить ответ сервера невозможно, иначе подпись станет не валидна
        Instant start = Instant.now();
        SignedMessage<VerifyResponse> signedMessage = certificationCenter.secureVerifyCertificate(securedMessage.getCertificate());
        if (!signatureManager.verify(signedMessage.getBytes(), signedMessage.getSign(), generalCertificate.getPublicKey(), signedMessage)) {
            throw new SecurityException("Invalid Sign in VerifyResponse");
        }
        VerifyResponse verifyResponse = signedMessage.getMessage();
        if (!verifyResponse.getCertificate().equals(securedMessage.getCertificate())) {
            throw new SecurityException("Different certificate in VerifyResponse");
        }
        if (!verifyResponse.isValid()) {
            throw new SecurityException("Invalid Certificate in message");
        }
        // Если кто-решить подсунуть устаревший ответ сервера
        if (verifyResponse.getCreated().isBefore(start)) {
            throw new SecurityException("Invalid response created time");
        }
        byte[] decrypted = securedMessage.decrypt(keyPair.getPrivate());
        if (!signatureManager.verify(decrypted, securedMessage.getSign(), securedMessage.getCertificate().getPublicKey())) {
            throw new SecurityException("Invalid Sign in Message");
        }

        System.out.printf("\n %s received message from %s: %s \n", name, securedMessage.getCertificate().getSubjectName(), new String(decrypted));
    }

    @Override
    public Certificate getCertificate() {
        return certificate;
    }

    @Override
    public <T> SignedMessage<T> sendSignedMessage(T message) {
        SignedMessage<T> signedMessage = new SignedMessageImpl<>(message, signatureManager.getSignAlg(), signatureManager.getParameters());
        signedMessage.setSign(signatureManager.sign(signedMessage.getBytes()));
        return signedMessage;
    }

}
