package com.t1.security.config;


import com.t1.security.entity.Role;
import domain.CertificateRepository;
import domain.CertificationCenter;
import domain.CryptoFactory;
import domain.SignatureManager;
import infrastructure.CryptoFactoryImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
    private final CryptoFactory cryptoFactory;
    private final KeyPair keyPair;

    @Autowired
    public WebSecurityConfig(CertificateRepository certificateRepository,
                             @Value("${crypto.sign-alg}") String SIGN_ALG,
                             @Value("${crypto.key-gen-alg}") String KEY_GEN_ALG,
                             @Value("${crypto.key-pair-gen-alg}") String KEY_PAIR_GEN_ALG,
                             @Value("${crypto.key-size}") String KEY_SIZE,
                             @Value("${crypto.asymmetric-alg}") String ASYMMETRIC_ALG,
                             @Value("${crypto.symmetric-alg}") String SYMMETRIC_ALG,
                             PublicKey publicKey, PrivateKey privateKey
    ) throws NoSuchAlgorithmException {
        int keySize = Integer.parseInt(KEY_SIZE);
        keyPair = new KeyPair(publicKey, privateKey);
        cryptoFactory = new CryptoFactoryImpl(certificateRepository, keyPair, SIGN_ALG, new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1
        ), KEY_GEN_ALG, KEY_PAIR_GEN_ALG, keySize, ASYMMETRIC_ALG, SYMMETRIC_ALG);
    }

    @Bean
    public CryptoFactory cryptoFactory() {
        return cryptoFactory;
    }

    @Bean
    KeyPair keyPair() {
        return keyPair;
    }

    @Bean
    SignatureManager signatureManager() {
        return cryptoFactory.createSignatureManager();
    }

    @Bean
    CertificationCenter certificationCenter(CertificateRepository certificateRepository) {
        return cryptoFactory.getCertificationCenter();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthTokenFilter authTokenFilter, AuthEntryPointJwt unauthorizedHandler) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers("/swagger-ui/**").permitAll()
                        .requestMatchers("/docs/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/users/admin").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.GET, "/users/premium").hasRole(Role.PREMIUM_USER.name())
                        .anyRequest().authenticated())
                .addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
