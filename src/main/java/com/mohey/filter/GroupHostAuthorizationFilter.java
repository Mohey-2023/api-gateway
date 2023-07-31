package com.mohey.filter;

import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.io.buffer.DataBufferUtils;
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
public class GroupHostAuthorizationFilter extends AbstractGatewayFilterFactory<GroupHostAuthorizationFilter.Config> {
    Environment env;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public GatewayFilter apply(GroupHostAuthorizationFilter.Config config) {
        return (((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "no authorization header", HttpStatus.UNAUTHORIZED);
            }
            return extractMemberUuid(request)
                    .flatMap(memberUuid -> {
                        String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                        String jwt = authorizationHeader.replace("Bearer", "");
                        Claims jwtClaims = Jwts.parser().setSigningKey(env.getProperty("jwt.secret")).parseClaimsJws(jwt).getBody();

                        if (!isJwtExpired(jwtClaims)) {
                            return onTokenExpired(exchange, "JWT token has expired", HttpStatus.UNAUTHORIZED);
                        }

                        if (!isJwtValid(jwtClaims, memberUuid)) {
                            return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
                        }

                        return chain.filter(exchange);
                    })
                    .switchIfEmpty(Mono.defer(() -> onError(exchange, "Member UUID is empty", HttpStatus.UNAUTHORIZED)))
                    .onErrorResume(e -> onError(exchange, "Error extracting Member UUID", HttpStatus.UNAUTHORIZED));
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

    private boolean isJwtValid(Claims jwtClaims, String memberUuid) {
        String subject;

        try {
            subject = jwtClaims.getSubject();
        } catch (Exception e) {
            return false;
        }

        if (!subject.equals(memberUuid)) {
            return false;
        }

        return true;
    }

    public static class Config {
    }

    public static Mono<String> extractMemberUuid(ServerHttpRequest request) {
        return DataBufferUtils.join(request.getBody())
                .map(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    return new String(bytes, StandardCharsets.UTF_8);
                })
                .flatMap(jsonString -> {
                    try {
                        JsonNode jsonNode = objectMapper.readTree(jsonString);
                        return Mono.justOrEmpty(jsonNode.get("memberuuid").asText());
                    } catch (Exception e) {
                        return Mono.error(e);
                    }
                });
    }

}
