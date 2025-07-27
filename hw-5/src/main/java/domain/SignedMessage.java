package domain;

import java.security.spec.AlgorithmParameterSpec;

public interface SignedMessage<T> {
    byte[] getBytes();

    T getMessage();

    byte[] getSign();
    String getSignAlg();
    AlgorithmParameterSpec getSignProperties();

    void setSign(byte[] sign);
}
