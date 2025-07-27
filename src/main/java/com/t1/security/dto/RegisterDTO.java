package com.t1.security.dto;

import com.t1.security.entity.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

import java.util.Set;

public record RegisterDTO(
        @Size(min = 5, message = "Username must be at least 5 characters") String userName,
        @Email(message = "Email must be a format email") @Size(min = 5, message = "Email must be at least 5 characters") String email,
        @Size(min = 5, message = "Password must be at least 5 characters") String password,
        Set<Role> role) {
}
