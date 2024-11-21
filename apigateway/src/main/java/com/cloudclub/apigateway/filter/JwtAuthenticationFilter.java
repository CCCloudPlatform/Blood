package com.cloudclub.apigateway.filter;

import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    @Autowired
    private JwtUtil jwtUtil;

    public JwtAuthenticationFilter() {
        super(Config.class);
    }

    public static class Config {
        // 필터 설정이 필요한 경우 여기에 추가
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            // /login, /register 등 인증이 필요없는 경로는 패스
            if (request.getURI().getPath().contains("/login") ||
                    request.getURI().getPath().contains("/register")) {
                return chain.filter(exchange);
            }

            // Authorization 헤더 확인
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                throw new RuntimeException("Missing authorization header");
            }

            String authHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                throw new RuntimeException("Invalid authorization header");
            }

            // JWT 토큰 추출 및 검증
            String token = authHeader.substring(7);
            try {
                Claims claims = jwtUtil.validateToken(token);

                // 검증된 사용자 정보를 헤더에 추가
                ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                        .header("Authorization", authHeader)
                        .header("X-User-Id", claims.getSubject())
                        .header("X-User-Role", claims.get("role", String.class))
                        .build();

                return chain.filter(exchange.mutate().request(modifiedRequest).build());
            } catch (Exception e) {
                throw new RuntimeException("Invalid token");
            }
        });
    }
} 