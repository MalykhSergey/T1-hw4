package com.t1.security.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import infrastructure.CipherMessage;

import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public final class CipherMessageDTO {
    private byte[] encryptedData;
    private byte[] encryptedSessionKey;
    private byte[] sign;
    private CertificateDTO certificateDTO;
    private String signAlg;
    private AlgorithmParameterSpec signProperties;
    private String keyGenAlg;
    private String asymmetricAlg;
    private String symmetricAlg;

    public CipherMessageDTO() {
    }

    public CipherMessageDTO(byte[] encryptedData, byte[] encryptedSessionKey, byte[] sign,
                            CertificateDTO certificateDTO,
                            String signAlg, AlgorithmParameterSpec signProperties, String keyGenAlg,
                            String asymmetricAlg, String symmetricAlg) {
        this.encryptedData = encryptedData;
        this.encryptedSessionKey = encryptedSessionKey;
        this.sign = sign;
        this.certificateDTO = certificateDTO;
        this.signAlg = signAlg;
        this.signProperties = signProperties;
        this.keyGenAlg = keyGenAlg;
        this.asymmetricAlg = asymmetricAlg;
        this.symmetricAlg = symmetricAlg;
    }

    public CipherMessageDTO(CipherMessage cipherMessage) {
        this(cipherMessage.getEncryptedData(),
                cipherMessage.getEncryptedSessionKey(),
                cipherMessage.getSign(),
                new CertificateDTO(cipherMessage.getCertificate()),
                cipherMessage.getSignAlg(),
                cipherMessage.getSignProperties(),
                cipherMessage.getKeyGenAlg(),
                cipherMessage.getAsymmetricAlg(),
                cipherMessage.getSymmetricAlg());
    }

    @JsonIgnore
    public CipherMessage getCipherMessage() throws NoSuchAlgorithmException, InvalidKeySpecException {
        return new CipherMessage(certificateDTO.getCertificate(), this.encryptedSessionKey, this.encryptedData, this.sign, this.signAlg, this.signProperties, this.keyGenAlg, this.asymmetricAlg, this.symmetricAlg);
    }

    public byte[] getEncryptedData() {
        return encryptedData;
    }

    public void setEncryptedData(byte[] encryptedData) {
        this.encryptedData = encryptedData;
    }

    public byte[] getEncryptedSessionKey() {
        return encryptedSessionKey;
    }

    public void setEncryptedSessionKey(byte[] encryptedSessionKey) {
        this.encryptedSessionKey = encryptedSessionKey;
    }

    public byte[] getSign() {
        return sign;
    }

    public void setSign(byte[] sign) {
        this.sign = sign;
    }

    public CertificateDTO getCertificateDTO() {
        return certificateDTO;
    }

    public void setCertificateDTO(CertificateDTO certificateDTO) {
        this.certificateDTO = certificateDTO;
    }

    public String getSignAlg() {
        return signAlg;
    }

    public void setSignAlg(String signAlg) {
        this.signAlg = signAlg;
    }

    public AlgorithmParameterSpec getSignProperties() {
        return signProperties;
    }

    public void setSignProperties(Object ignored) {
        // Для гибкой работы, объект должен создаваться на основе параметров
        // Если все используют один алгоритм, то пойдёт и так
        this.signProperties = new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1
        );
    }

    public String getKeyGenAlg() {
        return keyGenAlg;
    }

    public void setKeyGenAlg(String keyGenAlg) {
        this.keyGenAlg = keyGenAlg;
    }

    public String getAsymmetricAlg() {
        return asymmetricAlg;
    }

    public void setAsymmetricAlg(String asymmetricAlg) {
        this.asymmetricAlg = asymmetricAlg;
    }

    public String getSymmetricAlg() {
        return symmetricAlg;
    }

    public void setSymmetricAlg(String symmetricAlg) {
        this.symmetricAlg = symmetricAlg;
    }
}
