package com.t1.security.repository;

import com.t1.security.entity.AuthCertificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthCertificateRepository extends JpaRepository<AuthCertificate, String> {
    Optional<AuthCertificate> findByUser_Name(String name);
    void removeByUser_Name(String name);
}
