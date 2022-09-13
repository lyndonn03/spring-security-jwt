package io.lpamintuan.securityjwt.components;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtsBuilder {

    private SecretKey key;

    public JwtsBuilder() {
        this.key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }

    public String generate(String subject) {
        return Jwts.builder().setSubject(subject).signWith(key).compact();
    }
    
}
