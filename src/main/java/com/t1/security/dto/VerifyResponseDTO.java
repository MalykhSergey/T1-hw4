package com.t1.security.dto;

import com.fasterxml.jackson.annotation.JsonCreator;

import java.time.Instant;

public class VerifyResponseDTO {
    private final CertificateDTO certificateDTO;
    private final Boolean valid;
    private final Instant created;


    @JsonCreator
    public VerifyResponseDTO(CertificateDTO certificateDTO, boolean valid, Instant created) {
        this.certificateDTO = certificateDTO;
        this.valid = valid;
        this.created = created;
    }

    public CertificateDTO getCertificateDTO() {
        return certificateDTO;
    }

    public boolean getValid() {
        return valid;
    }

    public Instant getCreated() {
        return created;
    }
}
