package io.lpamintuan.securityjwt._config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class AppJwtAuthenticationFilter extends OncePerRequestFilter {

    private final String AUTH_HEADER = "XX-AUTH-XX";
    
    private final AuthenticationManager manager;

    private final AppAuthenticationEntryPoint entrypoint;

    public AppJwtAuthenticationFilter(AuthenticationManager manager, AppAuthenticationEntryPoint entrypoint) {
        this.entrypoint = entrypoint;
        this.manager = manager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authToken = request.getHeader(AUTH_HEADER);

        try {
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(authToken, null);
            Authentication authResult = manager.authenticate(token);

            if(authResult.isAuthenticated())
                SecurityContextHolder.getContext().setAuthentication(authResult);

            filterChain.doFilter(request, response);
        } catch(AuthenticationException ae) {
            entrypoint.commence(request, response, ae);
        }
        
    }
    
}
