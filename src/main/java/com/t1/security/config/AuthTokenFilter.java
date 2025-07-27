package com.t1.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.t1.security.dto.CipherMessageDTO;
import com.t1.security.dto.UserDTO;
import com.t1.security.services.AuthService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);
    private final ObjectMapper objectMapper;
    private final AuthService authService;

    @Autowired
    public AuthTokenFilter(ObjectMapper objectMapper, AuthService authService
    ) {
        this.objectMapper = objectMapper;
        this.authService = authService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            if (request.getHeader("SecuredMessageProtocol") != null) {
                CipherMessageDTO cipherMessageDTO = objectMapper.readValue(request.getInputStream().readAllBytes(), CipherMessageDTO.class);
                byte[] decrypted = authService.decryptAndVerify(cipherMessageDTO);
                UserDTO user = authService.loadUserDTOByName(cipherMessageDTO.getCertificateDTO().getSubjectName());
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        user, null, user.getRoles());
                SecurityContextHolder.getContext().setAuthentication(authentication);
                request = new DecryptedHttpServletRequest(request, decrypted);
            }

        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}