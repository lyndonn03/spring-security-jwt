package io.lpamintuan.securityjwt.services;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import io.lpamintuan.securityjwt.models.UserInfo;

@Service
public class AppService {

    private UserDetailsService userDetailsService;

    public AppService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public UserInfo getUserInfo(String username) {
        return (UserInfo) userDetailsService.loadUserByUsername(username);
    }
    
}
