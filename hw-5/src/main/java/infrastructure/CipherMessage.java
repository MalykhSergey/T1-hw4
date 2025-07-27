package infrastructure;

import domain.Certificate;
import domain.SecuredMessage;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class CipherMessage implements SecuredMessage {

    private final byte[] encryptedData;
    private final byte[] encryptedSessionKey;
    private final byte[] sign;
    private final Certificate certificate;
    private final String signAlg;
    private final AlgorithmParameterSpec signProperties;
    private final String keyGenAlg;
    private final String asymmetricAlg;
    private final String symmetricAlg;

    public CipherMessage(Certificate senderCertificate, PublicKey receiverKey, byte[] data, byte[] sign, String signAlg, AlgorithmParameterSpec signProperties, String keyGenAlg, String asymmetricAlg, String symmetricAlg) {
        this.signAlg = signAlg;
        this.signProperties = signProperties;
        this.keyGenAlg = keyGenAlg;
        this.asymmetricAlg = asymmetricAlg;
        this.symmetricAlg = symmetricAlg;
        this.certificate = senderCertificate;
        try {
            this.sign = sign;
            SecretKey sessionKey = KeyGenerator.getInstance(keyGenAlg).generateKey();
            this.encryptedData = encryptData(sessionKey, data);
            this.encryptedSessionKey = encryptSessionKey(sessionKey, receiverKey);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    public CipherMessage(Certificate senderCertificate, byte[] encryptedSessionKey, byte[] data, byte[] sign, String signAlg, AlgorithmParameterSpec signProperties, String keyGenAlg, String asymmetricAlg, String symmetricAlg) {
        this.encryptedData = data;
        this.encryptedSessionKey = encryptedSessionKey;
        this.sign = sign;
        this.signAlg = signAlg;
        this.signProperties = signProperties;
        this.keyGenAlg = keyGenAlg;
        this.asymmetricAlg = asymmetricAlg;
        this.symmetricAlg = symmetricAlg;
        this.certificate = senderCertificate;
    }

    private byte[] encryptSessionKey(SecretKey sessionKey, PublicKey receiverKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        Cipher asymmetricCypher = Cipher.getInstance(asymmetricAlg);
        asymmetricCypher.init(Cipher.ENCRYPT_MODE, receiverKey);
        return asymmetricCypher.doFinal(sessionKey.getEncoded());
    }

    private byte[] encryptData(SecretKey sessionKey, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        Cipher symmetricCypher = Cipher.getInstance(symmetricAlg);
        symmetricCypher.init(Cipher.ENCRYPT_MODE, sessionKey);
        byte[] iv = symmetricCypher.getIV();
        ByteArrayOutputStream combinedData = new ByteArrayOutputStream();
        combinedData.write(iv);
        combinedData.write(symmetricCypher.doFinal(data));
        return combinedData.toByteArray();
    }

    @Override
    public byte[] decrypt(PrivateKey privateKey) {
        try {
            byte[] sessionKey = decryptSessionKey(privateKey);
            SecretKey symmetric = new SecretKeySpec(sessionKey, keyGenAlg);
            return decryptData(symmetric);
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt message", e);
        }
    }

    private byte[] decryptSessionKey(PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher rsaCipher = Cipher.getInstance(asymmetricAlg);
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return rsaCipher.doFinal(encryptedSessionKey);
    }

    public byte[] decryptData(SecretKey sessionKey) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher symmetricCipher = Cipher.getInstance(symmetricAlg);
        int ivLength = symmetricCipher.getBlockSize();
        byte[] iv = new byte[ivLength];
        System.arraycopy(encryptedData, 0, iv, 0, ivLength);
        byte[] actualEncryptedData = new byte[encryptedData.length - ivLength];
        System.arraycopy(encryptedData, ivLength, actualEncryptedData, 0, actualEncryptedData.length);
        symmetricCipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(iv));
        return symmetricCipher.doFinal(actualEncryptedData);
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
    public Certificate getCertificate() {
        return certificate;
    }

    public byte[] getEncryptedData() {
        return encryptedData;
    }

    public byte[] getEncryptedSessionKey() {
        return encryptedSessionKey;
    }

    public AlgorithmParameterSpec getSignProperties() {
        return signProperties;
    }

    public String getKeyGenAlg() {
        return keyGenAlg;
    }

    public String getAsymmetricAlg() {
        return asymmetricAlg;
    }

    public String getSymmetricAlg() {
        return symmetricAlg;
    }
}
