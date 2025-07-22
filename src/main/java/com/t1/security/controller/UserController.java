package com.t1.security.controller;

import com.t1.security.dto.UserDTO;
import io.swagger.v3.oas.annotations.Operation;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
public class UserController {
    @Operation(summary = "Returns user info")
    @GetMapping("/me")
    public UserDTO getCurrentUser(@AuthenticationPrincipal UserDTO user) {
        return user;
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
