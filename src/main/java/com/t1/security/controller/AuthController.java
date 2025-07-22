package com.t1.security.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.t1.security.dto.LoginDTO;
import com.t1.security.dto.RegisterDTO;
import com.t1.security.dto.TokensDTO;
import com.t1.security.services.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterDTO registerDTO) {
        authService.register(registerDTO);
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<TokensDTO> login(@RequestBody LoginDTO loginDTO) throws JsonProcessingException {
        TokensDTO tokens = authService.authenticate(loginDTO);
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokensDTO> refreshToken(@RequestParam String refreshToken) throws JsonProcessingException {
        TokensDTO tokens = authService.refreshToken(refreshToken);
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestParam String refreshToken) {
        authService.revokeToken(refreshToken);
        return ResponseEntity.ok("Refresh token revoked successfully");
    }
}