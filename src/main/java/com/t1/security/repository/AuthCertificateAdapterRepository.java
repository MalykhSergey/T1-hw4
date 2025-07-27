package com.t1.security.repository;

import com.t1.security.entity.AuthCertificate;
import domain.Certificate;
import domain.CertificateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

@Repository
public class AuthCertificateAdapterRepository implements CertificateRepository {
    private final AuthCertificateRepository authCertificateRepository;
    private final UserRepository userRepository;

    @Autowired
    public AuthCertificateAdapterRepository(AuthCertificateRepository authCertificateRepository, UserRepository userRepository) {
        this.authCertificateRepository = authCertificateRepository;
        this.userRepository = userRepository;
    }

    @Override
    public Certificate findByUserName(String name) {
        Optional<AuthCertificate> authCertificate = authCertificateRepository.findByUser_Name(name);
        if (authCertificate.isEmpty())
            return null;
        try {
            return authCertificate.get().getCertificate();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void save(Certificate certificate) {
        authCertificateRepository.save(new AuthCertificate(certificate, userRepository.findOneByName(certificate.getSubjectName()).get()));
    }

    @Override
    public void removeByName(String name) {
        authCertificateRepository.removeByUser_Name(name);
    }
}
