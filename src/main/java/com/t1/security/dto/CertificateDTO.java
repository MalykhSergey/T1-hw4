package com.t1.security.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import domain.Certificate;
import infrastructure.CertificateImpl;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Objects;

public final class CertificateDTO {
    private final String subjectName;
    private final String serialNumber;
    private final byte[] publicKey;
    private final String keyAlg;
    private final Date issueDate;
    private final Date expiryDate;
    private final byte[] signature;
    private final String signAlg;
    private final String issuerName;

    @JsonCreator
    public CertificateDTO(String subjectName, String serialNumber, byte[] publicKey, String keyAlg, Date issueDate, Date expiryDate, byte[] signature, String signAlg, String issuerName) {
        this.subjectName = subjectName;
        this.serialNumber = serialNumber;
        this.publicKey = publicKey;
        this.keyAlg = keyAlg;
        this.issueDate = issueDate;
        this.expiryDate = expiryDate;
        this.signature = signature;
        this.signAlg = signAlg;
        this.issuerName = issuerName;
    }

    public CertificateDTO(Certificate certificate) {
        this.subjectName = certificate.getSubjectName();
        this.publicKey = certificate.getPublicKey().getEncoded();
        this.keyAlg = certificate.getPublicKey().getAlgorithm();
        this.issueDate = certificate.getIssueDate();
        this.expiryDate = certificate.getExpiryDate();
        this.signature = certificate.getSignature();
        this.signAlg = certificate.getSignatureAlg();
        this.issuerName = certificate.getIssuerName();
        this.serialNumber = certificate.getSerialNumber();
    }

    @JsonIgnore
    public Certificate getCertificate() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance(this.keyAlg);
        PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(this.publicKey));
        CertificateImpl certificate = new CertificateImpl(subjectName, publicKey, this.getIssueDate(), this.getExpiryDate(), this.serialNumber, this.issuerName);
        certificate.setSignature(this.signature, this.signAlg);
        return certificate;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        CertificateDTO that = (CertificateDTO) o;
        return Objects.equals(subjectName, that.subjectName) && Objects.equals(serialNumber, that.serialNumber) && Arrays.equals(publicKey, that.publicKey) && Objects.equals(keyAlg, that.keyAlg) && Objects.equals(issueDate, that.issueDate) && Objects.equals(expiryDate, that.expiryDate) && Objects.deepEquals(signature, that.signature) && Objects.equals(signAlg, that.signAlg) && Objects.equals(issuerName, that.issuerName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subjectName, serialNumber, Arrays.hashCode(publicKey), keyAlg, issueDate, expiryDate, Arrays.hashCode(signature), signAlg, issuerName);
    }

    public String getSubjectName() {
        return subjectName;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public String getKeyAlg() {
        return keyAlg;
    }

    public Date getIssueDate() {
        return issueDate;
    }

    public Date getExpiryDate() {
        return expiryDate;
    }

    public byte[] getSignature() {
        return signature;
    }

    public String getSignAlg() {
        return signAlg;
    }

    public String getIssuerName() {
        return issuerName;
    }
}
