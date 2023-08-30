package com.mohey.apigateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class MemberIdentificationAuthorizationFilter extends AuthorizationFilter {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    public MemberIdentificationAuthorizationFilter(Environment env) {
        super(env);
    }


    //    @Override
//    public GatewayFilter apply(GroupHostAuthorizationFilter.Config config) {
//        return (((exchange, chain) -> {
//            ServerHttpRequest request = exchange.getRequest();
//
//            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
//                return onError(exchange, "no authorization header", HttpStatus.UNAUTHORIZED);
//            }
//            return extractMemberUuidFromRequest(request)
//                    .flatMap(leaderUuid -> {
//                        Claims jwtClaims = this.extractJwtClaimsFromRequest(request);
//
//                        if (!isJwtExpired(jwtClaims)) {
//                            return onTokenExpired(exchange, "JWT token has expired", HttpStatus.UNAUTHORIZED);
//                        }
//
//                        if (!isJwtValid(jwtClaims, leaderUuid)) {
//                            return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
//                        }
//
//                        return chain.filter(exchange);
//                    })
//                    .switchIfEmpty(Mono.defer(() -> onError(exchange, "Leader UUID is empty", HttpStatus.UNAUTHORIZED)))
//                    .onErrorResume(e ->{
//                        e.printStackTrace();
//                        return onError(exchange, "Error extracting Member UUID", HttpStatus.UNAUTHORIZED);
//                    } );
//        }));
//    }
    @Override
    public GatewayFilter apply(Config config) {
        return (((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            String clientIp = request.getRemoteAddress().getAddress().getHostAddress();

            if (allowedIps.contains(clientIp)) {
                return chain.filter(exchange);
            }
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "no authorization header", HttpStatus.UNAUTHORIZED);
            }
            try {
                Claims jwtClaims = extractJwtClaimsFromRequest(request);
                String memberUuid = request.getHeaders().getFirst("member-uuid");
                if (!isJwtValid(jwtClaims, memberUuid)) {
                    return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
                }
            } catch (ExpiredJwtException e) {
                return onTokenExpired(exchange, "JWT token has expired", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        }));
    }

    private boolean isJwtValid(Claims jwtClaims, String memberUuid) {
        String subject;

        try {
            subject = jwtClaims.get("memberUuid", String.class);
        } catch (Exception e) {
            return false;
        }

        if (!subject.equals(memberUuid)) {
            return false;
        }

        return true;
    }

}
