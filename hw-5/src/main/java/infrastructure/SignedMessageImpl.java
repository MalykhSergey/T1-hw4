package infrastructure;

import domain.SignedMessage;

import java.security.spec.AlgorithmParameterSpec;

public class SignedMessageImpl<T> implements SignedMessage<T> {
    private final T message;
    private byte[] sign;
    private final String signAlg;
    private final AlgorithmParameterSpec signProperties;

    public SignedMessageImpl(T message, String signAlg, AlgorithmParameterSpec signProperties) {
        this.message = message;
        this.signAlg = signAlg;
        this.signProperties = signProperties;
    }

    @Override
    public byte[] getBytes() {
        return message.toString().getBytes();
    }

    @Override
    public T getMessage() {
        return message;
    }

    @Override
    public byte[] getSign() {
        return sign;
    }

    @Override
    public String getSignAlg() {
        return signAlg;
    }

    @Override
    public AlgorithmParameterSpec getSignProperties() {
        return signProperties;
    }

    @Override
    public void setSign(byte[] sign) {
        this.sign = sign;
    }
}
