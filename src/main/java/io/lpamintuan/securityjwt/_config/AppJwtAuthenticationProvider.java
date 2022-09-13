package io.lpamintuan.securityjwt._config;

import java.util.HashSet;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.lpamintuan.securityjwt.components.JwtsBuilder;

@Component
public class AppJwtAuthenticationProvider implements AuthenticationProvider {

    private final JwtsBuilder jwtsBuilder;

    public AppJwtAuthenticationProvider(JwtsBuilder jwtsBuilder) {
        this.jwtsBuilder = jwtsBuilder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        try {
            if(authentication.getName() == null || authentication.getName().isBlank())
                return new UsernamePasswordAuthenticationToken(null, null);
            Jws<Claims> verifiedClaims = jwtsBuilder.validate(authentication.getName());
            Authentication result = 
                new UsernamePasswordAuthenticationToken(verifiedClaims.getBody().getSubject(), null, new HashSet<>());
            return result;
        } catch(JwtException ae) {
            throw new BadCredentialsException("Invalid token.");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
    
}
