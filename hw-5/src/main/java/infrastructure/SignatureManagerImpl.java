package infrastructure;

import domain.SignatureManager;
import domain.SignedMessage;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class SignatureManagerImpl implements SignatureManager {
    private Signature signSignature;
    private Signature verifySignature;
    private AlgorithmParameterSpec parameterSpec;

    SignatureManagerImpl(String alg, AlgorithmParameterSpec parameterSpec) {
        signSignature = setSignSignature(alg, parameterSpec);
        setVerifySignature(alg, parameterSpec);
    }

    private void setVerifySignature(String alg, AlgorithmParameterSpec parameterSpec) {
        try {
            this.verifySignature = Signature.getInstance(alg);
            verifySignature.setParameter(parameterSpec);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private Signature setSignSignature(String alg, AlgorithmParameterSpec parameterSpec) {
        try {
            signSignature = Signature.getInstance(alg);
            signSignature.setParameter(parameterSpec);
            this.parameterSpec = parameterSpec;
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        return signSignature;
    }

    @Override
    public byte[] sign(byte[] data) {
        try {
            signSignature.update(data);
            return signSignature.sign();
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean verify(byte[] data, byte[] sign, PublicKey verifyKey) {
        try {
            verifySignature.initVerify(verifyKey);
            verifySignature.update(data);
            return verifySignature.verify(sign);
        } catch (SignatureException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public <T> boolean verify(byte[] data, byte[] sign, PublicKey verifyKey, SignedMessage<T> signedMessage) {
        try {
            setVerifySignature(signedMessage.getSignAlg(), signedMessage.getSignProperties());
            verifySignature.initVerify(verifyKey);
            verifySignature.update(data);
            return verifySignature.verify(sign);
        } catch (SignatureException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void setSignKey(PrivateKey privateKey) {
        try {
            signSignature.initSign(privateKey);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public AlgorithmParameterSpec getParameters() {
        return parameterSpec;
    }

    @Override
    public String getSignAlg() {
        return signSignature.getAlgorithm();
    }
}
