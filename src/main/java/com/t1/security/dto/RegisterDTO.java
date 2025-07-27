package com.t1.security.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.t1.security.entity.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Set;

public record RegisterDTO(
        @Size(min = 5, message = "Username must be at least 5 characters") String userName,
        @Email(message = "Email must be a format email") @Size(min = 5, message = "Email must be at least 5 characters") String email,
        @Size(min = 5, message = "Password must be at least 5 characters") String password,
        @NotNull byte[] publicKey,
        @NotNull String keyAlg,
        Set<Role> role) {
    public RegisterDTO(String name, String email, String password, PublicKey publicKey, String keyAlg, Set<Role> roles) {
        this(name, email, password, publicKey.getEncoded(), keyAlg, roles);
    }

    @JsonIgnore
    public PublicKey genPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance(this.keyAlg);
        return kf.generatePublic(new X509EncodedKeySpec(publicKey));
    }
}
