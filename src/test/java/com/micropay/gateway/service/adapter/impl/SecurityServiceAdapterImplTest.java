package com.micropay.gateway.service.adapter.impl;

import com.micropay.gateway.config.GatewayConfig;
import com.micropay.gateway.dto.AuthResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SecurityServiceAdapterImplTest {

    private RestTemplate restTemplate;
    private SecurityServiceAdapterImpl securityServiceAdapter;

    @BeforeEach
    void setUp() {
        restTemplate = mock(RestTemplate.class);
        securityServiceAdapter = new SecurityServiceAdapterImpl(restTemplate);
    }

    @Test
    void refreshAccessToken_shouldReturnAuthResponse_whenStatusOk() {
        String userId = "user-123";
        AuthResponse expectedResponse = new AuthResponse("newAccessToken", "newRefreshToken");
        ResponseEntity<AuthResponse> responseEntity = new ResponseEntity<>(expectedResponse, HttpStatus.OK);

        when(restTemplate.exchange(
                eq(GatewayConfig.SECURITY_REFRESH_TOKEN_URL),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(AuthResponse.class)
        )).thenReturn(responseEntity);

        AuthResponse result = securityServiceAdapter.refreshAccessToken(userId);

        assertNotNull(result);
        assertEquals(expectedResponse, result);
        verify(restTemplate, times(1)).exchange(
                eq(GatewayConfig.SECURITY_REFRESH_TOKEN_URL),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(AuthResponse.class)
        );
    }

    @Test
    void refreshAccessToken_shouldReturnNull_whenStatusNotOk() {
        ResponseEntity<AuthResponse> responseEntity = new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);

        when(restTemplate.exchange(
                eq(GatewayConfig.SECURITY_REFRESH_TOKEN_URL),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(AuthResponse.class)
        )).thenReturn(responseEntity);

        AuthResponse result = securityServiceAdapter.refreshAccessToken("user-123");

        assertNull(result);
    }

    @Test
    void refreshAccessToken_shouldReturnNull_whenExceptionThrown() {
        when(restTemplate.exchange(
                anyString(),
                any(HttpMethod.class),
                any(HttpEntity.class),
                eq(AuthResponse.class)
        )).thenThrow(new RuntimeException("Network error"));

        AuthResponse result = securityServiceAdapter.refreshAccessToken("user-123");

        assertNull(result);
    }
}
