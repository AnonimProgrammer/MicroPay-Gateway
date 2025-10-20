package com.micropay.gateway.filter;

import com.micropay.gateway.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
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

    public static final String HEADER_USER_ID = "X-User-Id";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        if (shouldSkip(path)) {
            return chain.filter(exchange);
        }
        String accessToken = jwtService.extractToken(exchange.getRequest().getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION));

        if (path.contains("/admin")) {
            return validateAdminAccess(exchange, chain, accessToken);
        }
        return handleToken(exchange, chain, accessToken);
    }

    private Mono<Void> validateAdminAccess(
            ServerWebExchange exchange, WebFilterChain chain, String accessToken
    ) {
        if (isValidToken(accessToken)) {
            String role = jwtService.extractRole(accessToken);

            if (!"ADMIN".equalsIgnoreCase(role)) {
                return forbidden(exchange);
            }
            return chain.filter(exchange);
        }
        return unauthorized(exchange);
    }

    private Mono<Void> handleToken(ServerWebExchange exchange, WebFilterChain chain, String accessToken) {
        if (isValidToken(accessToken)) {
            return forwardWithUserId(exchange, chain, jwtService.extractUserId(accessToken));
        }
        return unauthorized(exchange);
    }

    private boolean isValidToken(String token) {
        return token != null && jwtService.isValidToken(token);
    }

    private Mono<Void> forwardWithUserId(ServerWebExchange exchange, WebFilterChain chain, String userId) {
        ServerHttpRequest mutatedRequest = exchange.getRequest()
                .mutate()
                .header(HEADER_USER_ID, userId)
                .build();
        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        return writeError(exchange, HttpStatus.UNAUTHORIZED, "Invalid access token.");
    }

    private Mono<Void> forbidden(ServerWebExchange exchange) {
        return writeError(exchange, HttpStatus.FORBIDDEN, "Unauthorized access.");
    }

    private Mono<Void> writeError(ServerWebExchange exchange, HttpStatus status, String message) {
        byte[] bytes = String.format("{\"error\":\"%s\"}", message).getBytes();
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        return exchange.getResponse().writeWith(
                Mono.just(exchange.getResponse().bufferFactory().wrap(bytes))
        );
    }

    private boolean shouldSkip(String path) {
        return path.contains("/auth") || path.contains("/actuator");
    }

}
