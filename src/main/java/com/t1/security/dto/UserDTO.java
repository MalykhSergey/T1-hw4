package com.t1.security.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.t1.security.entity.Role;
import com.t1.security.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.Set;

public class UserDTO implements UserDetails {
    private Long id;
    private String name;
    private String email;
    private Set<Role> roles;
    @JsonIgnore
    private String password;
    private CertificateDTO certificateDTO;

    public UserDTO() {
    }

    public UserDTO(User user) throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.id = user.getId();
        this.name = user.getName();
        this.email = user.getEmail();
        this.roles = user.getRoles();
        this.password = user.getPassword();
        this.certificateDTO = new CertificateDTO(user.getAuthCertificate().getCertificate());
    }

    public String getEmail() {
        return email;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    @JsonIgnore
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    @JsonIgnore
    public String getUsername() {
        return name;
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public CertificateDTO getCertificateDTO() {
        return certificateDTO;
    }

    public void setCertificateDTO(CertificateDTO certificateDTO) {
        this.certificateDTO = certificateDTO;
    }
}
