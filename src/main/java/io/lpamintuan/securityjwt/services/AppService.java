package io.lpamintuan.securityjwt.services;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import io.lpamintuan.securityjwt.controllers.templates.AuthenticationTemplate;
import io.lpamintuan.securityjwt.models.UserInfo;

@Service
public class AppService {

    private final UserDetailsService userDetailsService;

    private final PasswordEncoder passwordEncoder;

    public AppService(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    public UserInfo getUserInfo(String username) {
        return (UserInfo) userDetailsService.loadUserByUsername(username);
    }

    public String signinUser(AuthenticationTemplate creds) {
        UserDetails user = userDetailsService.loadUserByUsername(creds.getUsername());

        if(!passwordEncoder.matches(creds.getPassword(), user.getPassword()))
            throw new BadCredentialsException("Invalid credentials.");
            
        return "sampleToken";
    }
    
}
