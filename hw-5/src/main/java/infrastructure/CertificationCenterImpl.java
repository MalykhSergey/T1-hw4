package infrastructure;

import domain.*;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Date;
import java.util.UUID;

public class CertificationCenterImpl implements CertificationCenter {
    private final SignatureManager signatureManager;
    private final CertificateRepository certificateRepository;
    private final KeyPair keyPair;
    private final String name;
    private final Certificate selfCertificate;

    public CertificationCenterImpl(
            String name,
            CertificateRepository certificateRepository,
            SignatureManager signatureManager,
            KeyPairGenerator keyPairGenerator
    ) throws InvalidKeyException {
        keyPair = keyPairGenerator.generateKeyPair();
        signatureManager.setSignKey(keyPair.getPrivate());
        this.signatureManager = signatureManager;
        this.certificateRepository = certificateRepository;
        this.name = name;
        String serialNumber = UUID.randomUUID().toString();
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + 10 * 365L * 24 * 60 * 60 * 1000);
        Certificate cert = new CertificateImpl(
                name,
                keyPair.getPublic(),
                now,
                expiryDate,
                serialNumber,
                name
        );
        cert.setSignature(signatureManager.sign(cert.toString().getBytes()), signatureManager.getSignAlg());
        this.selfCertificate = cert;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Certificate getCertificate(String name) {
        if (name.equals(this.name))
            return selfCertificate;
        return certificateRepository.findByUserName(name);
    }

    @Override
    public Certificate issueCertificate(String subjectName, PublicKey publicKey) {
        if (certificateRepository.findByUserName(subjectName) != null) {
            throw new SecurityException("Such subjectName already has certificate");
        }
        String serialNumber = UUID.randomUUID().toString();
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + 365L * 24 * 60 * 60 * 1000);


        Certificate cert = new CertificateImpl(
                subjectName,
                publicKey,
                now,
                expiryDate,
                serialNumber,
                name
        );

        cert.setSignature(signatureManager.sign(cert.toString().getBytes()), signatureManager.getSignAlg());
        certificateRepository.save(cert);
        return cert;
    }

    @Override
    public SignedMessage<VerifyResponse> secureVerifyCertificate(Certificate certificate) {
        VerifyResponse verifyResponse = new VerifyResponseImpl(certificate, unsecureVerifyCertificate(certificate));
        SignedMessage<VerifyResponse> verifyResponseSigned = new SignedMessageImpl<>(verifyResponse, signatureManager.getSignAlg(), signatureManager.getParameters());
        verifyResponseSigned.setSign(signatureManager.sign(verifyResponseSigned.getBytes()));
        return verifyResponseSigned;
    }

    @Override
    public boolean unsecureVerifyCertificate(Certificate certificate) {
        if (!signatureManager.verify(certificate.toString().getBytes(), certificate.getSignature(), keyPair.getPublic()))
            return false;
        Certificate containedCert = certificateRepository.findByUserName(certificate.getSubjectName());
        if (containedCert==null){
            return false;
        }
        Date now = new Date();
        if (!now.before(certificate.getExpiryDate())) {
            return false;
        }
        return containedCert.getSerialNumber().equals(certificate.getSerialNumber());
    }

    @Override
    public void revokeCertificate(SignedMessage<String> signedSubjectName) {
        PublicKey verifyKey = certificateRepository.findByUserName(signedSubjectName.getMessage()).getPublicKey();
        if (!signatureManager.verify(signedSubjectName.getBytes(), signedSubjectName.getSign(), verifyKey)) {
            throw new SecurityException("Invalid sign in signedSubjectName");
        }
        certificateRepository.removeByName(signedSubjectName.getMessage());
    }
}
