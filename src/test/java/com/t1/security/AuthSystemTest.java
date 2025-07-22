package com.t1.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.t1.security.dto.LoginDTO;
import com.t1.security.dto.RegisterDTO;
import com.t1.security.dto.TokensDTO;
import com.t1.security.entity.RefreshToken;
import com.t1.security.entity.Role;
import com.t1.security.entity.User;
import com.t1.security.repository.RefreshTokenRepository;
import com.t1.security.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class AuthSystemTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_PASSWORD = "password123";
    private static final String ADMIN_USERNAME = "admin";
    private static final String ADMIN_EMAIL = "admin@example.com";
    private static final String PREMIUM_USERNAME = "premium";
    private static final String PREMIUM_EMAIL = "premium@example.com";

    @BeforeEach
    void setUp() {
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Успешная регистрация всех типов пользователей")
    void testSuccessfulRegistration() throws Exception {
        Role[] roles = {Role.GUEST, Role.ADMIN, Role.PREMIUM_USER};
        for (Role role : roles) {
            RegisterDTO registerDTO = new RegisterDTO(role.name(), role.name() + TEST_EMAIL, TEST_PASSWORD, Set.of(role));
            mockMvc.perform(post("/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(registerDTO)))
                    .andExpect(status().isOk())
                    .andExpect(content().string("User registered successfully"));
            User savedUser = userRepository.findOneByName(registerDTO.userName()).orElse(null);
            assertNotNull(savedUser);
            assertEquals(registerDTO.email(), savedUser.getEmail());
            assertTrue(passwordEncoder.matches(TEST_PASSWORD, savedUser.getPassword()));
            assertEquals(Set.of(role), savedUser.getRoles());
        }
    }

    @Test
    @DisplayName("Регистрация пользователя с несколькими ролями")
    void testMultipleRolesRegistration() throws Exception {
        RegisterDTO registerDTO = new RegisterDTO(TEST_USERNAME, TEST_EMAIL, TEST_PASSWORD,
                Set.of(Role.PREMIUM_USER, Role.GUEST));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerDTO)))
                .andExpect(status().isOk());

        User savedUser = userRepository.findOneByName(TEST_USERNAME).orElse(null);
        assertNotNull(savedUser);
        assertEquals(Set.of(Role.PREMIUM_USER, Role.GUEST), savedUser.getRoles());
    }

    @Test
    @DisplayName("Дублирование имени пользователя")
    void testRegistrationWithDuplicateUsername() throws Exception {
        createTestUser(TEST_USERNAME, TEST_EMAIL, TEST_PASSWORD, Set.of(Role.GUEST));
        RegisterDTO registerDTO = new RegisterDTO(TEST_USERNAME, "another@example.com", TEST_PASSWORD, Set.of(Role.GUEST));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerDTO)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Успешная аутентификация существующего пользователя")
    void testSuccessfulAuthentication() throws Exception {
        createTestUser(TEST_USERNAME, TEST_EMAIL, TEST_PASSWORD, Set.of(Role.GUEST));

        LoginDTO loginDTO = new LoginDTO(TEST_USERNAME, TEST_PASSWORD);

        String response = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginDTO)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andReturn().getResponse().getContentAsString();

        TokensDTO tokens = objectMapper.readValue(response, TokensDTO.class);
        assertNotNull(tokens.accessToken());
        assertNotNull(tokens.refreshToken());

        assertTrue(refreshTokenRepository.findByToken(tokens.refreshToken()).isPresent());
    }

    @Test
    @DisplayName("Неверный пароль")
    void testAuthenticationWithWrongPassword() throws Exception {
        createTestUser(TEST_USERNAME, TEST_EMAIL, TEST_PASSWORD, Set.of(Role.GUEST));

        LoginDTO loginDTO = new LoginDTO(TEST_USERNAME, "wrongpassword");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginDTO)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Несуществующий пользователь")
    void testAuthenticationWithNonExistentUser() throws Exception {
        LoginDTO loginDTO = new LoginDTO("nonexistent", TEST_PASSWORD);

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginDTO)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Доступ к защищенному ресурсу с валидным токеном")
    void testAccessProtectedResourceWithValidToken() throws Exception {
        User user = createTestUser(TEST_USERNAME, TEST_EMAIL, TEST_PASSWORD, Set.of(Role.GUEST));
        String accessToken = authenticateAndGetTokens(TEST_USERNAME, TEST_PASSWORD).accessToken();

        mockMvc.perform(get("/users/me")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value(TEST_USERNAME))
                .andExpect(jsonPath("$.email").value(TEST_EMAIL))
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    @DisplayName("Запрет доступа к защищенному ресурсу без токена")
    void testAccessProtectedResourceWithoutToken() throws Exception {
        mockMvc.perform(get("/users/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Запрет доступа к защищенному ресурсу с невалидным токеном")
    void testAccessProtectedResourceWithInvalidToken() throws Exception {
        mockMvc.perform(get("/users/me")
                        .header("Authorization", "Bearer invalid-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Доступ к админ-панели")
    void testAdminAccessControl() throws Exception {
        createTestUser(ADMIN_USERNAME, ADMIN_EMAIL, TEST_PASSWORD, Set.of(Role.ADMIN));
        String adminToken = authenticateAndGetTokens(ADMIN_USERNAME, TEST_PASSWORD).accessToken();

        createTestUser(TEST_USERNAME, TEST_EMAIL, TEST_PASSWORD, Set.of(Role.GUEST));
        String guestToken = authenticateAndGetTokens(TEST_USERNAME, TEST_PASSWORD).accessToken();

        mockMvc.perform(get("/users/admin")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(content().string("Admin panel should be here"));

        mockMvc.perform(get("/users/admin")
                        .header("Authorization", "Bearer " + guestToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Доступ к премиум-контенту только для премиум пользователей")
    void testPremiumAccessControl() throws Exception {
        createTestUser(PREMIUM_USERNAME, PREMIUM_EMAIL, TEST_PASSWORD, Set.of(Role.PREMIUM_USER));
        String premiumToken = authenticateAndGetTokens(PREMIUM_USERNAME, TEST_PASSWORD).accessToken();

        createTestUser(TEST_USERNAME, TEST_EMAIL, TEST_PASSWORD, Set.of(Role.GUEST));
        String guestToken = authenticateAndGetTokens(TEST_USERNAME, TEST_PASSWORD).accessToken();

        mockMvc.perform(get("/users/premium")
                        .header("Authorization", "Bearer " + premiumToken))
                .andExpect(status().isOk())
                .andExpect(content().string("Premium access extension should be here"));

        mockMvc.perform(get("/users/premium")
                        .header("Authorization", "Bearer " + guestToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Успешное обновление токена с валидным refresh token")
    void testSuccessfulTokenRefresh() throws Exception {
        createTestUser(TEST_USERNAME, TEST_EMAIL, TEST_PASSWORD, Set.of(Role.GUEST));
        TokensDTO initialTokens = authenticateAndGetTokens(TEST_USERNAME, TEST_PASSWORD);
        Thread.sleep(1000);
        String response = mockMvc.perform(post("/auth/refresh")
                        .param("refreshToken", initialTokens.refreshToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andReturn().getResponse().getContentAsString();

        TokensDTO newTokens = objectMapper.readValue(response, TokensDTO.class);
        assertNotEquals(initialTokens.accessToken(), newTokens.accessToken());
    }

    @Test
    @DisplayName("Ошибка при обновлении токена с несуществующим refresh token")
    void testTokenRefreshWithInvalidRefreshToken() throws Exception {
        mockMvc.perform(post("/auth/refresh")
                        .param("refreshToken", "invalid-refresh-token"))
                .andExpect(status().isBadRequest());
    }


    @Test
    @DisplayName("Успешный отзыв refresh token")
    void testSuccessfulTokenRevocation() throws Exception {
        createTestUser(TEST_USERNAME, TEST_EMAIL, TEST_PASSWORD, Set.of(Role.GUEST));
        TokensDTO tokens = authenticateAndGetTokens(TEST_USERNAME, TEST_PASSWORD);

        mockMvc.perform(post("/auth/logout")
                        .param("refreshToken", tokens.refreshToken()))
                .andExpect(status().isOk())
                .andExpect(content().string("Refresh token revoked successfully"));

        RefreshToken revokedToken = refreshTokenRepository.findByToken(tokens.refreshToken()).orElse(null);
        assertNotNull(revokedToken);
        assertTrue(revokedToken.isRevoked());
    }

    @Test
    @DisplayName("Ошибка при отзыве несуществующего refresh token")
    void testRevokeNonExistentRefreshToken() throws Exception {
        mockMvc.perform(post("/auth/logout")
                        .param("refreshToken", "non-existent-token"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Ошибка при обновлении токена с отозванным refresh token")
    void testTokenRefreshWithRevokedRefreshToken() throws Exception {
        createTestUser(TEST_USERNAME, TEST_EMAIL, TEST_PASSWORD, Set.of(Role.GUEST));
        TokensDTO tokens = authenticateAndGetTokens(TEST_USERNAME, TEST_PASSWORD);


        mockMvc.perform(post("/auth/logout")
                        .param("refreshToken", tokens.refreshToken()))
                .andExpect(status().isOk());

        mockMvc.perform(post("/auth/refresh")
                        .param("refreshToken", tokens.refreshToken()))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Множественные сессии для одного пользователя")
    void testMultipleSessionsForSameUser() throws Exception {
        createTestUser(TEST_USERNAME, TEST_EMAIL, TEST_PASSWORD, Set.of(Role.GUEST));

        TokensDTO tokens1 = authenticateAndGetTokens(TEST_USERNAME, TEST_PASSWORD);
        TokensDTO tokens2 = authenticateAndGetTokens(TEST_USERNAME, TEST_PASSWORD);


        mockMvc.perform(get("/users/me")
                        .header("Authorization", "Bearer " + tokens1.accessToken()))
                .andExpect(status().isOk());

        mockMvc.perform(get("/users/me")
                        .header("Authorization", "Bearer " + tokens2.accessToken()))
                .andExpect(status().isOk());


        mockMvc.perform(post("/auth/logout")
                        .param("refreshToken", tokens1.refreshToken()))
                .andExpect(status().isOk());

        mockMvc.perform(get("/users/me")
                        .header("Authorization", "Bearer " + tokens2.accessToken()))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Время жизни токенов")
    void testTimeExpirationForTokens() throws Exception {
        createTestUser(TEST_USERNAME, TEST_EMAIL, TEST_PASSWORD, Set.of(Role.GUEST));

        TokensDTO testUser = authenticateAndGetTokens(TEST_USERNAME, TEST_PASSWORD);


        mockMvc.perform(get("/users/me")
                        .header("Authorization", "Bearer " + testUser.accessToken()))
                .andExpect(status().isOk());

        Thread.sleep(2000);

        mockMvc.perform(get("/users/me")
                        .header("Authorization", "Bearer " + testUser.accessToken()))
                .andExpect(status().isUnauthorized());

        Thread.sleep(3000);
        String response = mockMvc.perform(post("/auth/refresh")
                        .param("refreshToken", testUser.refreshToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andReturn().getResponse().getContentAsString();
        TokensDTO newTokens = objectMapper.readValue(response, TokensDTO.class);
        assertNotEquals(newTokens.accessToken(), testUser.accessToken());
        assertNotEquals(newTokens.refreshToken(), testUser.refreshToken());
    }

    private User createTestUser(String username, String email, String password, Set<Role> roles) {
        User user = new User(0, username, passwordEncoder.encode(password), email, roles);
        return userRepository.save(user);
    }

    private TokensDTO authenticateAndGetTokens(String username, String password) throws Exception {
        LoginDTO loginDTO = new LoginDTO(username, password);

        String response = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginDTO)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        return objectMapper.readValue(response, TokensDTO.class);
    }
}