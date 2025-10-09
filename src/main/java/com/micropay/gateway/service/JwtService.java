package com.micropay.gateway.service;

public interface JwtService {

    boolean isValidToken(String token);

    String extractToken(String authHeader);

    String extractUserId(String token);

    String extractRole(String token);
}
