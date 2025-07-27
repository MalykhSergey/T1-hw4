package com.t1.security.entity;

import domain.Certificate;
import infrastructure.CertificateImpl;
import jakarta.persistence.*;
import org.hibernate.annotations.Cascade;
import org.hibernate.annotations.CascadeType;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

@Entity
public class AuthCertificate {
    @Id
    private String serialNumber;
    @OneToOne(optional = false)
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    @Cascade(CascadeType.ALL)
    private User user;
    @Column(nullable = false)
    private byte[] publicKey;
    @Column(nullable = false)
    private String publicKeyAlg;
    @Column(nullable = false)
    private Date issueDate;
    @Column(nullable = false)
    private Date expiryDate;
    @Column(nullable = false)
    private byte[] signature;
    @Column(nullable = false)
    private String signatureAlg;
    @Column(nullable = false)
    private String issuerName;

    public AuthCertificate() {
    }


    public AuthCertificate(Certificate certificate, User user) {
        if (!user.getName().equals(certificate.getSubjectName())) {
            throw new SecurityException("Name in certificate and user different");
        }
        this.user = user;
        this.serialNumber = certificate.getSerialNumber();
        this.publicKey = certificate.getPublicKey().getEncoded();
        this.publicKeyAlg = certificate.getPublicKey().getAlgorithm();
        this.issueDate = certificate.getIssueDate();
        this.expiryDate = certificate.getExpiryDate();
        this.signature = certificate.getSignature();
        this.signatureAlg = certificate.getSignatureAlg();
        this.issuerName = certificate.getIssuerName();
    }

    public AuthCertificate(String serialNumber, User user, byte[] publicKey, String publicKeyAlg, Date issueDate,
                           Date expiryDate, byte[] signature, String signatureAlg, String issuerName) {
        this.serialNumber = serialNumber;
        this.user = user;
        this.publicKey = publicKey;
        this.publicKeyAlg = publicKeyAlg;
        this.issueDate = issueDate;
        this.expiryDate = expiryDate;
        this.signature = signature;
        this.signatureAlg = signatureAlg;
        this.issuerName = issuerName;
    }

    public Certificate getCertificate() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance(this.getPublicKeyAlg());
        PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(this.getPublicKey()));
        Certificate certificate = new CertificateImpl(user.getName(), publicKey, this.getIssueDate(), this.getExpiryDate(), this.serialNumber, this.issuerName);
        certificate.setSignature(this.signature, this.signatureAlg);
        return certificate;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public Date getIssueDate() {
        return issueDate;
    }

    public void setIssueDate(Date issueDate) {
        this.issueDate = issueDate;
    }

    public Date getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(Date expiryDate) {
        this.expiryDate = expiryDate;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public String getIssuerName() {
        return issuerName;
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getSignatureAlg() {
        return signatureAlg;
    }

    public void setSignatureAlg(String signatureAlg) {
        this.signatureAlg = signatureAlg;
    }

    public String getPublicKeyAlg() {
        return publicKeyAlg;
    }

    public void setPublicKeyAlg(String publicKeyAlg) {
        this.publicKeyAlg = publicKeyAlg;
    }
}
