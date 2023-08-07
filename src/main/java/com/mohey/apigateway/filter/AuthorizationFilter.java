package com.mohey.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class AuthorizationFilter extends AbstractGatewayFilterFactory<AuthorizationFilter.Config> {
    Environment env;

    @Autowired
    public AuthorizationFilter(Environment env){
        super(Config.class);
        this.env = env;

    }

    @Override
    public GatewayFilter apply(Config config) {
        return (((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "no authorization header", HttpStatus.UNAUTHORIZED);
            }

            Claims jwtClaims = extractJwtClaimsFromRequest(request);


            if (!isJwtExpired(jwtClaims)) {
                return onTokenExpired(exchange, "JWT token has expired", HttpStatus.UNAUTHORIZED);
            }


            if (!isJwtValid(jwtClaims)) {
                return onError(exchange,"JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        }));
    }

    protected Claims extractJwtClaimsFromRequest(ServerHttpRequest request) {
        String jwt = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0).replace("Bearer", "");
        return Jwts.parser().setSigningKey(env.getProperty("jwt.secret")).parseClaimsJws(jwt).getBody();
    }

    protected Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        // Get the factory for data buffers
        DataBufferFactory bufferFactory = response.bufferFactory();

        // Create a data buffer with the error message
        DataBuffer buffer = bufferFactory.wrap(err.getBytes(StandardCharsets.UTF_8));

        // Write the error message to the response
        return response.writeWith(Mono.just(buffer));
    }

    protected Mono<Void> onTokenExpired(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        //auth쪽 토큰 재발급 url로 수정 필요
        response.getHeaders().add("WWW-Authenticate", "Bearer error=\"token_expired\", error_description=\"" + err + "\", error_uri=\"auth쪽 토큰 재발급 url\"");

        return response.setComplete();
    }


    protected boolean isJwtExpired(Claims jwtClaims) {
        try {

            Date expirationDate = jwtClaims.getExpiration();
            if (expirationDate == null) {
                return false;
            }

            Date now = new Date();
            return now.after(expirationDate);

        } catch (Exception e) {
            return true;
        }
    }

    protected boolean isJwtValid(Claims jwtClaims) {
        String subject;

        try {
            subject = jwtClaims.getSubject();
        }catch (Exception e){
            return false;
        }

        if (subject == null || subject.isEmpty()) {
            return false;
        }

        return true;
    }

    public static class Config {
    }
}
