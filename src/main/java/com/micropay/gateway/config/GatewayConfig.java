package com.micropay.gateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class GatewayConfig {

    public final static String SECURITY_REFRESH_TOKEN_URL = "http://localhost:8150/auth/refresh-access-token";

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public RouteLocator gatewayRoutes(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("transaction-service",
                        r -> r.path("/transactions/**", "/internal/transactions/**")
                                .filters(f -> f.circuitBreaker(c -> c
                                        .setName("transactionCB")
                                        .setFallbackUri("forward:/fallback")))
                                .uri("http://localhost:8100"))
                .route("payment-service",
                        r -> r.path("/payments/**", "/internal/payments/**")
                                .filters(f -> f.circuitBreaker(c -> c
                                        .setName("paymentCB")
                                        .setFallbackUri("forward:/fallback")))
                                .uri("http://localhost:8120"))
                .route("wallet-service",
                        r -> r.path("/wallets/**", "/internal/wallets/**")
                                .filters(f -> f.circuitBreaker(c -> c
                                        .setName("walletCB")
                                        .setFallbackUri("forward:/fallback")))
                                .uri("http://localhost:8110"))
                .route("security-service",
                        r -> r.path("/users/**", "/auth/**",
                                        "/internal/users/**", "/admin/users/**"
                                )
                                .filters(f -> f.circuitBreaker(c -> c
                                        .setName("securityCB")
                                        .setFallbackUri("forward:/fallback")))
                                .uri("http://localhost:8150"))
                .build();
    }

}
