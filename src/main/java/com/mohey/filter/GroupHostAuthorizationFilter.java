package com.mohey.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Date;

@Component
public class GroupHostAuthorizationFilter extends AbstractGatewayFilterFactory<GroupHostAuthorizationFilter.Config> {
    Environment env;


    @Override
    public GatewayFilter apply(GroupHostAuthorizationFilter.Config config) {
        return (((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "no authorization header", HttpStatus.UNAUTHORIZED);
            }


            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);

            String jwt = authorizationHeader.replace("Bearer", "");

            Claims jwtClaims = Jwts.parser().setSigningKey(env.getProperty("jwt.secret")).parseClaimsJws(jwt).getBody();

            if (!isJwtExpired(jwtClaims)) {
                return onTokenExpired(exchange, "JWT token has expired", HttpStatus.UNAUTHORIZED);
            }


            if (!isJwtValid(jwtClaims)) {
                return onError(exchange,"JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        }));
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        return response.setComplete();
    }

    private Mono<Void> onTokenExpired(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        //auth쪽 토큰 재발급 url로 수정 필요
        response.getHeaders().add("WWW-Authenticate", "Bearer error=\"token_expired\", error_description=\"" + err + "\", error_uri=\"auth쪽 토큰 재발급 url\"");

        return response.setComplete();
    }


    private boolean isJwtExpired(Claims jwtClaims) {
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

    private boolean isJwtValid(Claims jwtClaims) {
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
