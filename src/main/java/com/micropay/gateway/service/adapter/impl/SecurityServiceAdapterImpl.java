package com.micropay.gateway.service.adapter.impl;

import com.micropay.gateway.config.GatewayConfig;
import com.micropay.gateway.dto.AuthResponse;
import com.micropay.gateway.filter.AuthenticationWebFilter;
import com.micropay.gateway.service.adapter.SecurityServiceAdapter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
@RequiredArgsConstructor
public class SecurityServiceAdapterImpl implements SecurityServiceAdapter {

    private final RestTemplate restTemplate;

    @Override
    public AuthResponse refreshAccessToken(String userId) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set(AuthenticationWebFilter.HEADER_USER_ID, userId);
            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<AuthResponse> response = restTemplate.exchange(
                    GatewayConfig.SECURITY_REFRESH_TOKEN_URL,
                    HttpMethod.POST,
                    entity, AuthResponse.class
            );

            return response.getStatusCode() == HttpStatus.OK ? response.getBody() : null;
        } catch (Exception exception) {
            return null;
        }
    }

}
