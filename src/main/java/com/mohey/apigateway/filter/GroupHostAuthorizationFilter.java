package com.mohey.apigateway.filter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.core.env.Environment;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Component
public class GroupHostAuthorizationFilter extends AuthorizationFilter {
    Environment env;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    public GroupHostAuthorizationFilter(Environment env) {
        super(env);
    }

    @Override
    public GatewayFilter apply(GroupHostAuthorizationFilter.Config config) {
        return (((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "no authorization header", HttpStatus.UNAUTHORIZED);
            }
            return extractMemberUuidFromRequest(request)
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


    public static Mono<String> extractMemberUuidFromRequest(ServerHttpRequest request) {
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
