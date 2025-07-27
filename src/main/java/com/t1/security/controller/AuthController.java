package com.t1.security.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.t1.security.dto.CertificateDTO;
import com.t1.security.dto.RegisterDTO;
import com.t1.security.dto.SignedMessageDTO;
import com.t1.security.dto.VerifyResponseDTO;
import com.t1.security.services.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/certificate")
    public ResponseEntity<CertificateDTO[]> register(@Valid @RequestBody RegisterDTO registerDTO) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return new ResponseEntity<>(authService.register(registerDTO), HttpStatus.CREATED);
    }

    @GetMapping("/certificate")
    public ResponseEntity<SignedMessageDTO<CertificateDTO>> getCertificate(@RequestParam String subjectName) throws JsonProcessingException {
        return new ResponseEntity<>(authService.getCertificate(subjectName), HttpStatus.OK);
    }

    @PostMapping("/certificate/verify")
    public ResponseEntity<SignedMessageDTO<VerifyResponseDTO>> verify(@RequestBody CertificateDTO certificateDTO) throws JsonProcessingException, NoSuchAlgorithmException, InvalidKeySpecException {
        return new ResponseEntity<>(authService.verifyCertificate(certificateDTO), HttpStatus.OK);
    }

    @DeleteMapping("/certificate")
    public ResponseEntity<?> revokeCertificate(@RequestBody SignedMessageDTO<String> signedMessage) {
        authService.revokeCertificate(signedMessage);
        return ResponseEntity.ok("Deleted");
    }

}