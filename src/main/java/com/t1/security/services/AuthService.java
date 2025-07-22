package com.t1.security.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.t1.security.dto.LoginDTO;
import com.t1.security.dto.RegisterDTO;
import com.t1.security.dto.TokensDTO;
import com.t1.security.dto.UserDTO;
import com.t1.security.entity.RefreshToken;
import com.t1.security.entity.User;
import com.t1.security.repository.RefreshTokenRepository;
import com.t1.security.repository.UserRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final long refreshTokenExpirationS;
    private final long accessTokenExpirationS;

    private final SecretKey secretKey;

    private final ObjectMapper objectMapper;

    @Autowired
    public AuthService(
            UserRepository userRepository,
            RefreshTokenRepository refreshTokenRepository,
            PasswordEncoder passwordEncoder,
            ObjectMapper objectMapper,
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.refresh-token-expiration-s}") long refreshTokenExpirationS,
            @Value("${jwt.access-token-expiration-s}") long accessTokenExpirationS
    ) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenExpirationS = refreshTokenExpirationS;
        this.accessTokenExpirationS = accessTokenExpirationS;
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes());
        this.objectMapper = objectMapper;
    }

    public void register(RegisterDTO registerDto) {
        if (userRepository.findOneByName(registerDto.userName()).isPresent())
            throw new IllegalArgumentException("Username is already taken");
        User user = new User(0, registerDto.userName(), passwordEncoder.encode(registerDto.password()), registerDto.email(), registerDto.role());
        userRepository.save(user);
    }

    @Transactional
    public TokensDTO authenticate(LoginDTO loginDto) throws JsonProcessingException {
        User user = userRepository.findOneByName(loginDto.userName())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        if (!passwordEncoder.matches(loginDto.password(), user.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }
        String accessToken = generateAccessToken(new UserDTO(user));
        RefreshToken refreshToken = createRefreshToken(user);
        return new TokensDTO(accessToken, refreshToken.getToken());
    }

    private RefreshToken createRefreshToken(User user) {
        RefreshToken token = new RefreshToken(null, UUID.randomUUID().toString(), user, Instant.now(), Instant.now().plusSeconds(refreshTokenExpirationS), false);
        return refreshTokenRepository.save(token);
    }

    @Transactional
    public TokensDTO refreshToken(String requestRefreshToken) throws JsonProcessingException {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(requestRefreshToken)
                .orElseThrow(() -> new IllegalArgumentException("Refresh token not found"));
        if (refreshToken.isRevoked()) {
            throw new IllegalArgumentException("Refresh token is revoked");
        }
        if (refreshToken.getExpiresAt().isBefore(Instant.now())) {
            refreshTokenRepository.delete(refreshToken);
            refreshToken = createRefreshToken(refreshToken.getUser());
        }
        String newAccessToken = generateAccessToken(new UserDTO(refreshToken.getUser()));
        return new TokensDTO(newAccessToken, refreshToken.getToken());
    }

    public void revokeToken(String requestRefreshToken) {
        RefreshToken storedToken = refreshTokenRepository.findByToken(requestRefreshToken)
                .orElseThrow(() -> new IllegalArgumentException("Refresh token not found"));
        storedToken.setRevoked(true);
        refreshTokenRepository.save(storedToken);
    }

    public String generateAccessToken(UserDTO userDTO) throws JsonProcessingException {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + accessTokenExpirationS * 1000);
        return Jwts.builder().issuedAt(now).expiration(expiryDate).subject(objectMapper.writeValueAsString(userDTO)).signWith(this.secretKey).compact();
    }

    public UserDTO parseToken(String token) throws JsonProcessingException {
        return objectMapper.readValue(Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getSubject(), UserDTO.class);
    }
}
