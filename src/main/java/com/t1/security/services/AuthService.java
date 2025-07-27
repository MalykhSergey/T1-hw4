package com.t1.security.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.t1.security.dto.*;
import com.t1.security.entity.User;
import com.t1.security.repository.UserRepository;
import domain.Certificate;
import domain.CertificationCenter;
import domain.SignatureManager;
import infrastructure.CipherMessage;
import infrastructure.SignedMessageImpl;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;


    private final ObjectMapper objectMapper;
    private final SignatureManager signatureManager;
    private final CertificationCenter certificationCenter;
    private final KeyPair keyPair;

    @Autowired
    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            CertificationCenter certificationCenter,
            KeyPair keyPair,
            SignatureManager signatureManager,
            ObjectMapper objectMapper
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.objectMapper = objectMapper;
        this.signatureManager = signatureManager;
        this.certificationCenter = certificationCenter;
        this.keyPair = keyPair;
        signatureManager.setSignKey(keyPair.getPrivate());
    }

    @Transactional
    public CertificateDTO[] register(RegisterDTO registerDto) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (userRepository.findOneByName(registerDto.userName()).isPresent())
            throw new IllegalArgumentException("Username is already taken");
        User user = new User(0, registerDto.userName(), passwordEncoder.encode(registerDto.password()), registerDto.email(), registerDto.role());
        userRepository.save(user);
        Certificate certificate = certificationCenter.issueCertificate(user.getName(), registerDto.genPublicKey());
        CertificateDTO newCertificateDTO = new CertificateDTO(certificate);
        Certificate centerCertificate = certificationCenter.getCertificate("AuthService");
        CertificateDTO centerCertificateDTO = new CertificateDTO(centerCertificate);
        return new CertificateDTO[]{newCertificateDTO, centerCertificateDTO};
    }

    public SignedMessageDTO<CertificateDTO> getCertificate(String name) throws JsonProcessingException {
        CertificateDTO certificateDTO = new CertificateDTO(certificationCenter.getCertificate(name));
        SignedMessageImpl<CertificateDTO> certificateDTOSignedMessage = new SignedMessageImpl<>(certificateDTO, signatureManager.getSignAlg(), signatureManager.getParameters());
        certificateDTOSignedMessage.setSign(signatureManager.sign(objectMapper.writeValueAsBytes(certificateDTO)));
        return new SignedMessageDTO<>(certificateDTOSignedMessage);
    }

    public byte[] decryptAndVerify(CipherMessageDTO cipherMessageDTO) throws NoSuchAlgorithmException, InvalidKeySpecException {
        CipherMessage cipherMessage = cipherMessageDTO.getCipherMessage();
        byte[] decrypted = cipherMessage.decrypt(keyPair.getPrivate());
        if (!signatureManager.verify(decrypted, cipherMessage.getSign(), cipherMessage.getCertificate().getPublicKey())) {
            throw new SecurityException("Sign not valid");
        }
        return decrypted;
    }

    public <T> CipherMessageDTO sendCipherMessage(UserDTO receiver, T data) throws JsonProcessingException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] message = objectMapper.writeValueAsBytes(data);
        CipherMessageDTO cipherMessageDTO = new CipherMessageDTO(new CipherMessage(certificationCenter.getCertificate("AuthService"), receiver.getCertificateDTO().getCertificate().getPublicKey(), message, signatureManager.sign(message), signatureManager.getSignAlg(), signatureManager.getParameters(), "AES", "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "AES/CBC/PKCS5Padding"));
        return cipherMessageDTO;
    }

    public UserDTO loadUserDTOByName(String name) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return new UserDTO(userRepository.findOneByName(name).orElseThrow(() -> new RuntimeException("User not found")));
    }

    @Transactional
    public void revokeCertificate(SignedMessageDTO<String> signedMessage) {
        // Удаляется и пользователь
        certificationCenter.revokeCertificate(signedMessage.getSignedMessage());
    }

    public SignedMessageDTO<VerifyResponseDTO> verifyCertificate(CertificateDTO certificateDTO) throws NoSuchAlgorithmException, InvalidKeySpecException, JsonProcessingException {
        boolean isValid = certificationCenter.unsecureVerifyCertificate(certificateDTO.getCertificate());
        VerifyResponseDTO verifyResponseDTO = new VerifyResponseDTO(certificateDTO, isValid, Instant.now());
        SignedMessageDTO<VerifyResponseDTO> result = new SignedMessageDTO<>(verifyResponseDTO);
        result.setSign(signatureManager.sign(objectMapper.writeValueAsBytes(verifyResponseDTO)));
        result.setSignAlg(signatureManager.getSignAlg());
        result.setSignProperties(signatureManager.getParameters());
        return result;
    }
}
