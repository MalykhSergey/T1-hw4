package com.t1.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class KeyLoader {

    private final ResourceLoader resourceLoader;

    @Autowired
    public KeyLoader(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @Bean
    public PublicKey publicKey(@Value("${security.public-key}") String publicKey) throws Exception {
        Resource resource = resourceLoader.getResource("classpath:" + publicKey);
        String publicKeyPEM = new String(resource.getInputStream().readAllBytes());
        return parsePublicKey(publicKeyPEM);
    }

    @Bean
    public PrivateKey privateKey(@Value("${security.private-key}") String privateKey) throws Exception {
        Resource resource = resourceLoader.getResource("classpath:" + privateKey);
        String privateKeyPEM = new String(resource.getInputStream().readAllBytes());
        return parsePrivateKey(privateKeyPEM);
    }

    private RSAPublicKey parsePublicKey(String publicKeyPEM) throws Exception {
        String publicKeyContent = publicKeyPEM
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(publicKeyContent);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(spec);
    }

    private RSAPrivateKey parsePrivateKey(String privateKeyPEM) throws Exception {
        String privateKeyContent = privateKeyPEM
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(privateKeyContent);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(spec);
    }
}