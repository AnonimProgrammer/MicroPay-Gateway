package com.micropay.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class RequestLoggingWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();

        log.info("[Gateway] - Incoming request: {} {}", request.getMethod(), request.getURI());

        return chain.filter(exchange)
                .doOnSuccess(aVoid -> 
                    log.info("[Gateway] - Response status: {} for {} {}",
                        response.getStatusCode(), request.getMethod(), request.getURI()))
                .doOnError(throwable -> 
                    log.error("[Gateway] - Error for {} {}: {}",
                        request.getMethod(), request.getURI(), throwable.getMessage())
                );
    }
}
