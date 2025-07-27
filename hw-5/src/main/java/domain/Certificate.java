package domain;

import java.security.PublicKey;
import java.util.Date;

public interface Certificate {
    String getSerialNumber();

    String getSubjectName();

    PublicKey getPublicKey();

    Date getIssueDate();

    Date getExpiryDate();

    byte[] getSignature();

    void setSignature(byte[] signature, String signatureAlg);

    String getSignatureAlg();

    String getIssuerName();
}
