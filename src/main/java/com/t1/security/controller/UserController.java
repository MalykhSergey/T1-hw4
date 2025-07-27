package com.t1.security.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.t1.security.dto.CipherMessageDTO;
import com.t1.security.dto.UserDTO;
import com.t1.security.services.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@RestController
@RequestMapping("/users")
public class UserController {

    private final AuthService authService;

    public UserController(AuthService authService) {
        this.authService = authService;
    }

    @Operation(summary = "Returns user info")
    @GetMapping("/me")
    public CipherMessageDTO getCurrentUser(@AuthenticationPrincipal UserDTO user) throws JsonProcessingException, NoSuchAlgorithmException, InvalidKeySpecException {
        return authService.sendCipherMessage(user, user);
    }

    @Operation(summary = "Check admin role")
    @GetMapping("/admin")
    public String checkAdmin(@AuthenticationPrincipal UserDTO user) {
        return "Admin panel should be here";
    }

    @Operation(summary = "Check premium role")
    @GetMapping("/premium")
    public String checkPremium() {
        return "Premium access extension should be here";
    }
}
