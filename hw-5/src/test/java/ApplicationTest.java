import domain.*;
import infrastructure.CertificateImpl;
import infrastructure.CipherMessage;
import infrastructure.CryptoFactoryImpl;
import infrastructure.HashMapCertificateRepository;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ApplicationTest {
    private final CryptoFactory cryptoFactory;
    private final User alice;
    private final User bob;
    private final User charlie;

    public ApplicationTest() {
        cryptoFactory = new CryptoFactoryImpl(new HashMapCertificateRepository(), null);
        alice = cryptoFactory.createUser("Alice");
        bob = cryptoFactory.createUser("Bob");
        charlie = cryptoFactory.createUser("Charlie");
    }

    @Test
    void testLegitimateTransfer() {
        SecuredMessage message = alice.sendSecuredMessage(bob.getCertificate().getPublicKey(),
                "Hi Bob. It's Alice.".getBytes());
        assertDoesNotThrow(() -> bob.receiveMessage(message));
    }

    @Test
    void testDuplicateUserCreation() {
        assertThrows(SecurityException.class,
                () -> cryptoFactory.createUser("Alice"));
    }

    @Test
    void testEavesdroppingPrevention() {
        SecuredMessage message = alice.sendSecuredMessage(bob.getCertificate().getPublicKey(),
                "Secret".getBytes());
        User spy = cryptoFactory.createUser("Spy");
        assertThrows(Exception.class,
                () -> spy.receiveMessage(message));
    }

    @Test
    void testIntegrityProtection() {
        SecuredMessage original = alice.sendSecuredMessage(bob.getCertificate().getPublicKey(),
                "Original".getBytes());
        SecuredMessage tampered = new CipherMessage(
                alice.getCertificate(),
                bob.getCertificate().getPublicKey(),
                "Tampered".getBytes(),
                original.getSign(),
                original.getSignAlg(),
                cryptoFactory.getSignProperties(),
                cryptoFactory.getKeyGenAlg(),
                cryptoFactory.getAsymmetricAlg(),
                cryptoFactory.getSymmetricAlg()
        );
        assertThrows(Exception.class,
                () -> bob.receiveMessage(tampered));
    }

    @Test
    void testFakeCertificateRejection() {
        KeyPairGenerator keyGen = cryptoFactory.createKeyPairGenerator();
        KeyPair fakePair = keyGen.generateKeyPair();
        Certificate fakeCert = new CertificateImpl(
                "Alice",
                fakePair.getPublic(),
                new Date(),
                new Date(System.currentTimeMillis() + 1000000),
                "fake-serial",
                "FakeCC"
        );
        fakeCert.setSignature("FAKE_SIG".getBytes(), "fake");

        SecuredMessage fakeMsg = new CipherMessage(
                fakeCert,
                bob.getCertificate().getPublicKey(),
                "Hello".getBytes(),
                "FAKE_SIG".getBytes(),
                cryptoFactory.getSignAlg(),
                cryptoFactory.getSignProperties(),
                cryptoFactory.getKeyGenAlg(),
                cryptoFactory.getAsymmetricAlg(),
                cryptoFactory.getSymmetricAlg()
        );
        assertThrows(Exception.class,
                () -> bob.receiveMessage(fakeMsg));
    }

    @Test
    void testRevokedCertificate() {
        User david = cryptoFactory.createUser("David");
        CertificationCenter certificationCenter = cryptoFactory.getCertificationCenter();
        certificationCenter.revokeCertificate(david.sendSignedMessage(david.getName()));
        SecuredMessage msg = david.sendSecuredMessage(bob.getCertificate().getPublicKey(),
                "After revoke".getBytes());
        assertThrows(Exception.class,
                () -> bob.receiveMessage(msg));
        certificationCenter.issueCertificate(david.getName(), david.getCertificate().getPublicKey());
        assertThrows(Exception.class,
                () -> bob.receiveMessage(msg));
    }

    @Test
    void testExpiredCertificateRejection() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair expiredPair = keyGen.generateKeyPair();
        Certificate expired = new CertificateImpl(
                "Expired",
                expiredPair.getPublic(),
                new Date(),
                new Date(),
                "exp-serial",
                "SimpleCA"
        );
        expired.setSignature("SIG".getBytes(), "alg");
        SecuredMessage msg = new CipherMessage(
                expired,
                bob.getCertificate().getPublicKey(),
                "Test".getBytes(),
                "SIG".getBytes(),
                cryptoFactory.getSignAlg(),
                cryptoFactory.getSignProperties(),
                cryptoFactory.getKeyGenAlg(),
                cryptoFactory.getAsymmetricAlg(),
                cryptoFactory.getSymmetricAlg()
        );
        assertThrows(Exception.class,
                () -> bob.receiveMessage(msg));
    }

    @Test
    void testWrongRecipientProtection() {
        SecuredMessage confidential = alice.sendSecuredMessage(bob.getCertificate().getPublicKey(),
                "Secret".getBytes());
        assertDoesNotThrow(() -> bob.receiveMessage(confidential));
        assertThrows(Exception.class,
                () -> charlie.receiveMessage(confidential));
    }

    @Test
    void testSelfCommunication() {
        SecuredMessage finalMsg = charlie.sendSecuredMessage(alice.getCertificate().getPublicKey(),
                "Integrity OK".getBytes());
        assertDoesNotThrow(() -> alice.receiveMessage(finalMsg));
    }
}
