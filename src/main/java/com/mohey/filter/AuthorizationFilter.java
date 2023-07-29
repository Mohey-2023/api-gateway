package com.mohey.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

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

            }
            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);

            String jwt = authorizationHeader.replace("Bearer", "");

            if (!isJwtExpired(jwt)) {
                
            }


            if (!isJwtValid(jwt)) {

            }

            return chain.filter(exchange);
        }));
    }

    private boolean isJwtExpired(String jwt) {
        try {
            Jws<Claims> claimsJws = Jwts.parser().setSigningKey(env.getProperty("jwt.secret")).parseClaimsJws(jwt);
            Claims claims = claimsJws.getBody();

            Date expirationDate = claims.getExpiration();
            if (expirationDate == null) {
                return false;
            }

            Date now = new Date();
            return now.after(expirationDate);

        } catch (Exception e) {
            return true;
        }
    }

    private boolean isJwtValid(String jwt) {
        String subject;

        try {
            subject = Jwts.parser().setSigningKey(env.getProperty("jwt.secret"))
                    .parseClaimsJws(jwt).getBody()
                    .getSubject();
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
