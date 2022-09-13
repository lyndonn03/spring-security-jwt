package io.lpamintuan.securityjwt._config;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class AppAuthenticationManager implements AuthenticationManager {

    private ProviderManager manager;

    public AppAuthenticationManager(AppJwtAuthenticationProvider appJwtAuthenticationProvider) {
        this.manager = new ProviderManager(appJwtAuthenticationProvider);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return manager.authenticate(authentication);
    }
    
}
