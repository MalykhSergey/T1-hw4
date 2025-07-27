package domain;

import java.security.PublicKey;

public interface CertificationCenter {
    String getName();

    Certificate getCertificate(String name);

    Certificate issueCertificate(String subjectName, PublicKey publicKey);

    SignedMessage<VerifyResponse> secureVerifyCertificate(Certificate certificate);

    boolean unsecureVerifyCertificate(Certificate certificate);

    void revokeCertificate(SignedMessage<String> signedSubjectName);
}
