package com.campercodes.springSecurity.service;

import com.campercodes.springSecurity.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Slf4j
@Service
public class JwtService {
    public boolean isTokenValid(String jwt, User user) {
        String name = extractSubject(jwt);
        log.info("extractedName: " +name);
        log.info("user request name: " +name);
        log.info("equality:" + name.equals(user.getUsername()));
        log.info("expiry:" + extractExpiry(jwt).after(new Date()));
        return (name.equals(user.getUsername())) && extractExpiry(jwt).after(new Date());
    }
    public String extractSubject(String jwt) {
        return extractClaims(jwt, Claims::getSubject);
    }

    private Date extractExpiry(String jwt) {
        return extractClaims(jwt, Claims::getExpiration);
    }

    private <T> T extractClaims(String jwt, Function<Claims, T> resolver) {
        Claims claims = extractAllClaims(jwt);
        return resolver.apply(claims);
    }

    private Claims extractAllClaims(String jwt) {
        return Jwts
                .parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }

    private static final String SECRET_KEY = "VGhpcyBpcyB0aGUgYW1hemluZyBrZXkgZm9yIFNwcmluZyBzZWN1cml0eSBhcHAgbWFkZSBieSByYXRoaXNo";
    public String generateToken(User user) {
        long now = System.currentTimeMillis();
        return Jwts
                .builder()
                .subject(user.getUsername())
                .claim("role", user.getRole())
                .issuedAt(new Date(now))
                .expiration(new Date(now + 24*60*60*1000))
                .signWith(getSigningKey())
                .compact();
    }

    private SecretKey getSigningKey() {
        byte[] secretKey = Decoders.BASE64URL.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(secretKey);
    }
}
