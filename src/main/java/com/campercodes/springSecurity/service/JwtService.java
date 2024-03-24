package com.campercodes.springSecurity.service;

import com.campercodes.springSecurity.entity.Token;
import com.campercodes.springSecurity.entity.User;
import com.campercodes.springSecurity.repository.TokenRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.function.Function;

@Slf4j
@Service
public class JwtService {

    @Autowired
    private TokenRepository tokenRepository;
    public boolean isTokenValid(String jwt, User user){
        String name = null;
        try {
            name = extractSubject(jwt);

        Token token = tokenRepository.findByJwToken(jwt).orElseThrow(
                () -> new InvalidKeyException("Token not found in repo")
        );
        if(!token.isActive()) {
            log.info("Inactive token being used by the user. Re-authenticate user!!");
            throw new Exception("Inactive Token");
        }
        return (name.equals(user.getUsername()))
                && token.isActive()
                && extractExpiry(jwt).after(new Date());
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }
    public String extractSubject(String jwt) throws Exception{
        return extractClaims(jwt, Claims::getSubject);
    }

    private Date extractExpiry(String jwt) throws Exception{
        return extractClaims(jwt, Claims::getExpiration);
    }

    private <T> T extractClaims(String jwt, Function<Claims, T> resolver) throws Exception{
        Claims claims = extractAllClaims(jwt);
        return resolver.apply(claims);
    }

    private Claims extractAllClaims(String jwt) throws Exception{
        return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build().parseSignedClaims(jwt)
                    .getPayload();
    }

    private static final String
            SECRET_KEY = "VGhpcyBpcyB0aGUgYW1hemluZyBrZXkgZm9yIFNwcmluZyBzZWN1cml0eSBhcHAgbWFkZSBieSByYXRoaXNo";
    public String generateToken(User user) {
        inactivatePreviousUserTokens(user);
        long now = System.currentTimeMillis();
        String jwt = Jwts.builder()
                .subject(user.getUsername())
                .claim("role", user.getRole())
                .issuedAt(new Date(now))
                .expiration(new Date(now + 24*60*60*1000))
                .signWith(getSigningKey()).compact();
        saveTokenToRepo(user, jwt);
        return jwt;
    }

    private void saveTokenToRepo(User user, String jwt) {
        Token token = new Token();
        token.setActive(true);
        token.setUser(user);
        token.setJwToken(jwt);
        tokenRepository.save(token);
    }

    private void inactivatePreviousUserTokens(User user) {
        List<Token> tokens = tokenRepository.findByUserUsername(user.getUsername());
        tokens.forEach(t-> {
            t.setActive(false);
            tokenRepository.save(t);
        });
    }

    private SecretKey getSigningKey() {
        byte[] secretKey = Decoders.BASE64URL.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(secretKey);
    }
}
