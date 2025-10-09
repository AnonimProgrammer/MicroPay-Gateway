package com.micropay.gateway.service.impl;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceImplTest {

    private JwtServiceImpl jwtService;
    private String secret;
    private String validToken;
    private String tokenWithRole;
    private String invalidToken;

    @BeforeEach
    void setUp() {
        secret = java.util.Base64.getEncoder()
                .encodeToString("matrix-very-strong-secret-key1112131415161718".getBytes());
        jwtService = new JwtServiceImpl(secret);

        SecretKey key = io.jsonwebtoken.security.Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret)
        );

        validToken = Jwts.builder()
                .subject("12345")
                .expiration(new Date(System.currentTimeMillis() + 10000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        tokenWithRole = Jwts.builder()
                .subject("999")
                .claim("role", "ADMIN")
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        invalidToken = validToken + "corrupted";
    }

    @Test
    void isValidToken_shouldReturnTrueForValidToken() {
        assertTrue(jwtService.isValidToken(validToken));
    }

    @Test
    void isValidToken_shouldReturnFalseForInvalidToken() {
        assertFalse(jwtService.isValidToken(invalidToken));
    }

    @Test
    void extractToken_shouldReturnTokenWhenHeaderValid() {
        String header = "Bearer " + validToken;
        String result = jwtService.extractToken(header);
        assertEquals(validToken, result);
    }

    @Test
    void extractToken_shouldReturnNullWhenHeaderInvalid() {
        assertNull(jwtService.extractToken("InvalidHeader"));
        assertNull(jwtService.extractToken(null));
    }

    @Test
    void extractUserId_shouldReturnSubjectFromToken() {
        String subject = jwtService.extractUserId(validToken);
        assertEquals("12345", subject);
    }

    @Test
    void extractRole_shouldReturnRoleClaimFromToken() {
        String role = jwtService.extractRole(tokenWithRole);
        assertEquals("ADMIN", role);
    }
}
