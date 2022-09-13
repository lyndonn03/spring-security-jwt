package io.lpamintuan.securityjwt.services;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import io.lpamintuan.securityjwt.components.JwtsBuilder;
import io.lpamintuan.securityjwt.controllers.templates.AuthenticationTemplate;
import io.lpamintuan.securityjwt.models.UserInfo;

@Service
public class AppService {

    private final UserDetailsService userDetailsService;

    private final PasswordEncoder passwordEncoder;

    private final JwtsBuilder jwtsBuilder;

    public AppService(UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder, JwtsBuilder jwtsBuilder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.jwtsBuilder = jwtsBuilder;
    }

    public UserInfo getUserInfo(String username) {
        User user = (User) userDetailsService.loadUserByUsername(username);

        UserInfo userInfo = new UserInfo();
        userInfo.setUsername(user.getUsername());
        Set<GrantedAuthority> authorities = user.getAuthorities().stream()
                                                .collect(Collectors.toSet());

        userInfo.setAuthorities(authorities);
        userInfo.setIsAccountNonExpired(user.isAccountNonExpired());
        userInfo.setIsAccountNonLocked(user.isAccountNonLocked());
        userInfo.setIsCredentialsNonExpired(user.isCredentialsNonExpired());
        userInfo.setIsEnabled(user.isEnabled());

        return userInfo;

    }

    public String signinUser(AuthenticationTemplate creds) {
        UserDetails user = userDetailsService.loadUserByUsername(creds.getUsername());

        if (!passwordEncoder.matches(creds.getPassword(), user.getPassword()))
            throw new BadCredentialsException("Invalid credentials.");

        return jwtsBuilder.generate(creds.getUsername());
    }

}
