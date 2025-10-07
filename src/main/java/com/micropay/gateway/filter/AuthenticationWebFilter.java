package com.micropay.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.micropay.gateway.dto.AuthResponse;
import com.micropay.gateway.service.JwtService;
import com.micropay.gateway.service.adapter.SecurityServiceAdapter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class AuthenticationWebFilter implements WebFilter {

    private final JwtService jwtService;
    private final SecurityServiceAdapter securityServiceAdapter;
    private final ObjectMapper objectMapper;

    public static final String HEADER_USER_ID = "X-User-Id";
    public static final String HEADER_REFRESH_TOKEN = "X-Refresh-Token";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        if (shouldSkip(path)) {
            return chain.filter(exchange);
        }
        String accessToken = jwtService.extractToken(exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
        String refreshToken = exchange.getRequest().getHeaders().getFirst(HEADER_REFRESH_TOKEN);

        return handleTokens(exchange, chain, accessToken, refreshToken);
    }

    private Mono<Void> handleTokens(
            ServerWebExchange exchange, WebFilterChain chain,
            String accessToken, String refreshToken
    ) {
        if (isValidToken(accessToken)) {
            return forwardWithUserId(exchange, chain, jwtService.extractUserId(accessToken));
        }
        if (isValidToken(refreshToken)) {
            return handleRefreshToken(exchange, refreshToken);
        }
        return unauthorized(exchange);
    }

    private boolean isValidToken(String token) {
        return token != null && jwtService.isValidToken(token);
    }

    private Mono<Void> forwardWithUserId(
            ServerWebExchange exchange, WebFilterChain chain, String userId
    ) {
        ServerHttpRequest mutatedRequest = exchange.getRequest()
                .mutate()
                .header(HEADER_USER_ID, userId)
                .build();
        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private Mono<Void> handleRefreshToken(ServerWebExchange exchange, String refreshToken) {
        String userId = jwtService.extractUserId(refreshToken);
        AuthResponse newTokens = securityServiceAdapter.refreshAccessToken(userId);

        if (newTokens == null) {
            return unauthorized(exchange);
        }
        return writeResponse(exchange, newTokens);
    }

    private Mono<Void> writeResponse(ServerWebExchange exchange, Object body) {
        try {
            byte[] bytes = objectMapper.writeValueAsBytes(body);
            exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

            return exchange
                    .getResponse()
                    .writeWith(Mono.just(exchange.getResponse()
                    .bufferFactory().wrap(bytes)));
        } catch (Exception exception) {
            return unauthorized(exchange);
        }
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        byte[] bytes = "{\"error\":\"Unauthorized\"}".getBytes();
        exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                .bufferFactory().wrap(bytes)));
    }

    private boolean shouldSkip(String path) {
        return path.startsWith("/internal/") || path.startsWith("/admin")
                || path.equals("/auth/login") || path.equals("/auth/register");
    }

}
