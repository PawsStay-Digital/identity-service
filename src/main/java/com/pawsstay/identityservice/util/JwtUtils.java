package com.pawsstay.identityservice.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
@Component
public class JwtUtils {
    @Value("${app.jwt.secret}")
    private String SECRET_KEY;
    @Value("${app.jwt.expiration}")
    private Long SECRET_EXPIRATION;
    private SecretKey key;
    @PostConstruct
    public void init() {
        if (this.SECRET_KEY == null) {
            throw new RuntimeException("JWT Secret Key is not configured!");
        }
        // 此時 secretKeyString 已經有值了
        System.out.println(SECRET_KEY);
        this.key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(String email, String role) {
        return Jwts.builder()
                .subject(email)
                .claim("role", role)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + SECRET_EXPIRATION)) // 24小時有效期
                .signWith(key)
                .compact();
    }
}
