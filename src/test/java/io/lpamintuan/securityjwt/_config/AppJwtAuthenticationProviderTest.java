package io.lpamintuan.securityjwt._config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.lpamintuan.securityjwt.components.JwtsBuilder;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.BDDMockito.*;

import javax.crypto.SecretKey;

@ExtendWith(MockitoExtension.class)
public class AppJwtAuthenticationProviderTest {

    private AppJwtAuthenticationProvider appJwtAuthenticationProvider;

    @Mock
    private JwtsBuilder jwtsBuilder;

    @BeforeEach
    public void setUpEachTest() {
        this.appJwtAuthenticationProvider = new AppJwtAuthenticationProvider(jwtsBuilder);
    }

    @Test
    public void authenticateSuccessfullyIfJwtIsVerified() {
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        String testJwt = Jwts.builder().setSubject("testUsername").signWith(key).compact();
        Authentication auth = new UsernamePasswordAuthenticationToken(testJwt, null);
        given(jwtsBuilder.validate(any()))
                .willReturn(Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(testJwt));

        Authentication authResult = appJwtAuthenticationProvider.authenticate(auth);

        assertThat(authResult.getPrincipal()).isEqualTo("testUsername");
        assertThat(authResult.getAuthorities()).isNotNull();
        assertThat(authResult.isAuthenticated()).isTrue();
    }

    @Test
    public void authenticateAnonymouslyIfNoAuthTokenFound() {
        Authentication auth = new UsernamePasswordAuthenticationToken(null, null);

        Authentication authResult = appJwtAuthenticationProvider.authenticate(auth);

        assertThat(authResult.getPrincipal()).isNull();
        assertThat(authResult.isAuthenticated()).isFalse();
        verify(jwtsBuilder, never()).validate(any());
    }

    @Test
    public void authenticateThrowsExceptionIfTokenIsInvalid() {
        Authentication auth = new UsernamePasswordAuthenticationToken("testToken", null);
        given(jwtsBuilder.validate(any()))
            .willThrow(new JwtException(""));

        assertThatThrownBy(() -> appJwtAuthenticationProvider.authenticate(auth))
            .isInstanceOf(BadCredentialsException.class)
            .hasMessageContaining("Invalid token");

        verify(jwtsBuilder).validate("testToken");
    }

}
