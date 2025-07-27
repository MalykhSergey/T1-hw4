package domain;

import java.time.Instant;

public interface VerifyResponse {
    Certificate getCertificate();

    boolean isValid();

    Instant getCreated();
}
