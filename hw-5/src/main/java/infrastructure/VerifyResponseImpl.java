package infrastructure;

import domain.Certificate;
import domain.VerifyResponse;

import java.time.Instant;

public class VerifyResponseImpl implements VerifyResponse {
    private final Certificate certificate;
    private final boolean isValid;
    private final Instant created;

    public VerifyResponseImpl(Certificate certificate, boolean isValid) {
        this.certificate = certificate;
        this.isValid = isValid;
        this.created = Instant.now();
    }

    @Override
    public String toString() {
        return "VerifyResponse{" +
                "created=" + created +
                ", isValid=" + isValid +
                ", certificate=" + certificate +
                '}';
    }

    @Override
    public Certificate getCertificate() {
        return certificate;
    }

    @Override
    public boolean isValid() {
        return isValid;
    }

    @Override
    public Instant getCreated() {
        return created;
    }
}
