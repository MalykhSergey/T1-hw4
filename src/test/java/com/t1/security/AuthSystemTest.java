package com.t1.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.t1.security.dto.*;
import com.t1.security.entity.Role;
import domain.Certificate;
import domain.CryptoFactory;
import domain.SignatureManager;
import infrastructure.CipherMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class AuthSystemTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CryptoFactory cryptoFactory;

    private SignatureManager signatureManager;
    private KeyPair keyPair;
    private final String registrationProtocolHeader = "SecuredMessageProtocol";
    private final String protocolVersion = "v1";

    @BeforeEach
    void setUp() {
        // Генерируем пару ключей и инициализируем менеджер подписей
        keyPair = cryptoFactory.createKeyPairGenerator().generateKeyPair();
        signatureManager = cryptoFactory.createSignatureManager();
        signatureManager.setSignKey(keyPair.getPrivate());
    }

    @Test
    @DisplayName("Полный цикл: регистрация, проверка, отзыв")
    void testRegistrationAndCertificateLifecycle() throws Exception {
        RegisterDTO registerDTO = createRegisterDTO();

        // Выполняем регистрацию и получаем сертификаты
        CertificateDTO[] certs = performRegistration(registerDTO);
        Certificate senderCert = certs[0].getCertificate();
        Certificate centerCert = certs[1].getCertificate();

        // Проверяем информацию о пользователе
        verifyUserInfo(registerDTO, senderCert, centerCert);

        // Получаем сертификат собеседника
        verifyFetchSubjectCertificate(registerDTO.userName(), centerCert, certs[0]);

        // Проверяем верификацию сертификата
        verifyCertificateVerification(certs[0], centerCert);

        // Отзываем сертификат и проверяем доступ
        revokeCertificate(registerDTO.userName());

        // После отзыва сертификата доступ должен быть запрещен
        assertAccessDeniedAfterRevoke(senderCert, centerCert);
    }

    private RegisterDTO createRegisterDTO() {
        String uuid = UUID.randomUUID().toString();
        // Создаем DTO регистрации
        return new RegisterDTO(
                uuid, uuid+"@test.com", uuid,
                keyPair.getPublic(),
                keyPair.getPublic().getAlgorithm(),
                Set.of(Role.ADMIN)
        );
    }

    private CertificateDTO[] performRegistration(RegisterDTO dto) throws Exception {
        String requestJson = objectMapper.writeValueAsString(dto);
        String response = mockMvc.perform(post("/auth/certificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestJson))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        // Считаем регистрацию безопасной (либо она вообще выполняется до запуска сервисов)
        return objectMapper.readValue(response, CertificateDTO[].class);
    }

    private void verifyUserInfo(RegisterDTO dto, Certificate senderCert, Certificate centerCert) throws Exception {
        byte[] message = "Check Register".getBytes();
        CipherMessage cipherMessage = new CipherMessage(
                senderCert,
                centerCert.getPublicKey(),
                message,
                signatureManager.sign(message),
                signatureManager.getSignAlg(),
                cryptoFactory.getSignProperties(),
                cryptoFactory.getKeyGenAlg(),
                cryptoFactory.getAsymmetricAlg(),
                cryptoFactory.getSymmetricAlg()
        );
        CipherMessageDTO requestDto = new CipherMessageDTO(cipherMessage);
        String requestJson = objectMapper.writeValueAsString(requestDto);

        String response = mockMvc.perform(get("/users/me")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(registrationProtocolHeader, protocolVersion)
                        .content(requestJson))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        CipherMessageDTO responseDto = objectMapper.readValue(response, CipherMessageDTO.class);

        String plain = decryptAndVerifyMessage(responseDto, keyPair.getPrivate(), centerCert.getPublicKey());
        UserDTO userDTO = objectMapper.readValue(plain, UserDTO.class);

        assertEquals(dto.userName(), userDTO.getName());
        assertEquals(dto.role(), userDTO.getRoles());
    }

    private void verifyFetchSubjectCertificate(String subjectName, Certificate centerCert, CertificateDTO expectedCert) throws Exception {
        String response = mockMvc.perform(get("/auth/certificate")
                        .param("subjectName", subjectName))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        SignedMessageDTO signedMessage = objectMapper.readValue(response, SignedMessageDTO.class);
        CertificateDTO actual = objectMapper.convertValue(signedMessage.getMessage(), CertificateDTO.class);

        verify(objectMapper.writeValueAsBytes(actual), signedMessage.getSign(), centerCert.getPublicKey());
        assertEquals(expectedCert, actual);
    }

    private void verifyCertificateVerification(CertificateDTO certDto, Certificate centerCert) throws Exception {
        String certJson = objectMapper.writeValueAsString(certDto);
        String response = mockMvc.perform(post("/auth/certificate/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(certJson))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        SignedMessageDTO verifyResult = objectMapper.readValue(response, SignedMessageDTO.class);
        VerifyResponseDTO vr = objectMapper.convertValue(verifyResult.getMessage(), VerifyResponseDTO.class);
        byte[] bytes = objectMapper.writeValueAsBytes(vr);
        verify(bytes, verifyResult.getSign(), centerCert.getPublicKey());
    }

    private void revokeCertificate(String userName) throws Exception {
        SignedMessageDTO<String> revokeRequest = new SignedMessageDTO<>(userName);
        revokeRequest.setSign(signatureManager.sign(revokeRequest.getMessage().getBytes()));
        revokeRequest.setSignAlg(signatureManager.getSignAlg());
        revokeRequest.setSignProperties(signatureManager.getParameters());

        mockMvc.perform(delete("/auth/certificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(revokeRequest)))
                .andExpect(status().isOk());
    }

    private void assertAccessDeniedAfterRevoke(Certificate senderCert, Certificate centerCert) throws Exception {
        byte[] message = "Check access".getBytes();
        CipherMessage cipherMessage = new CipherMessage(
                senderCert,
                centerCert.getPublicKey(),
                message,
                signatureManager.sign(message),
                signatureManager.getSignAlg(),
                cryptoFactory.getSignProperties(),
                cryptoFactory.getKeyGenAlg(),
                cryptoFactory.getAsymmetricAlg(),
                cryptoFactory.getSymmetricAlg()
        );
        CipherMessageDTO requestDto = new CipherMessageDTO(cipherMessage);
        String requestJson = objectMapper.writeValueAsString(requestDto);
        mockMvc.perform(get("/users/me")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(registrationProtocolHeader, protocolVersion)
                        .content(requestJson)
                )
                .andExpect(status().isUnauthorized());
    }

    private String decryptAndVerifyMessage(CipherMessageDTO dto, PrivateKey key, PublicKey verifyKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        CipherMessage cm = dto.getCipherMessage();
        byte[] decrypted = cm.decrypt(key);
        verify(decrypted, cm.getSign(), verifyKey);
        return new String(decrypted);
    }

    private void verify(byte[] data, byte[] sign, PublicKey key) {
        if (!signatureManager.verify(data, sign, key)) {
            throw new SecurityException("Invalid sign on Message");
        }
    }
}
