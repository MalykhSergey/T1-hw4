package domain;

import java.security.PublicKey;

public interface User {
    String getName();

    SecuredMessage sendSecuredMessage(PublicKey receiverKey, byte[] data);

    void receiveMessage(SecuredMessage securedMessage);

    Certificate getCertificate();

    <T> SignedMessage<T> sendSignedMessage(T message);

}
