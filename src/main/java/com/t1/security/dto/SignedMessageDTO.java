package com.t1.security.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import domain.SignedMessage;
import infrastructure.SignedMessageImpl;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class SignedMessageDTO<T> {
    private T message;
    private byte[] sign;
    private String signAlg;
    private AlgorithmParameterSpec signProperties;

    public SignedMessageDTO() {
    }

    public SignedMessageDTO(T message) {
        this.message = message;
    }

    public SignedMessageDTO(SignedMessage<T> signedMessage) {
        this.message = signedMessage.getMessage();
        this.sign = signedMessage.getSign();
        this.signAlg = signedMessage.getSignAlg();
        this.signProperties = signedMessage.getSignProperties();
    }

    @JsonIgnore
    public SignedMessage<T> getSignedMessage() {
        SignedMessageImpl<T> signedMessage = new SignedMessageImpl<>(this.message, this.signAlg, this.signProperties);
        signedMessage.setSign(this.sign);
        return signedMessage;
    }

    public T getMessage() {
        return message;
    }

    public void setMessage(T message) {
        this.message = message;
    }

    public byte[] getSign() {
        return sign;
    }

    public void setSign(byte[] sign) {
        this.sign = sign;
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

    public void setSignProperties(Object object) {
        this.signProperties = new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1
        );
    }
}
