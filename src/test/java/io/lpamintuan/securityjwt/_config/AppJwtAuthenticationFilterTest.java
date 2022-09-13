package io.lpamintuan.securityjwt._config;

import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.util.HashSet;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.BDDMockito.*;

@ExtendWith(MockitoExtension.class)
public class AppJwtAuthenticationFilterTest {

    private AppJwtAuthenticationFilter filter;
    private MockHttpServletRequest mockReq;
    private MockHttpServletResponse mockRes;

    @Mock
    private FilterChain mockFilterChain;

    @Mock
    private AppAuthenticationEntryPoint appAuthenticationEntryPoint;

    @Mock
    private AuthenticationManager manager;

    @Mock
    private SecurityContext  securityContext;

    @BeforeEach
    public void setUpEachtest() {
        this.filter = new AppJwtAuthenticationFilter(manager, appAuthenticationEntryPoint);
        this.mockReq = new MockHttpServletRequest();
        this.mockRes = new MockHttpServletResponse();
        SecurityContextHolder.setContext(securityContext);
    }

    @Test
    public void doFilterInternalAuthenticatesSuccesfully() throws ServletException, IOException {
        
        UsernamePasswordAuthenticationToken  authResult = 
            new UsernamePasswordAuthenticationToken("testUsername","testPass", new HashSet<>());
        mockReq.addHeader("XX-AUTH-XX", "testJwt");
        ArgumentCaptor<UsernamePasswordAuthenticationToken> captor = ArgumentCaptor.forClass(UsernamePasswordAuthenticationToken.class);
        given(manager.authenticate(any()))
            .willReturn(authResult);

        filter.doFilter(mockReq, mockRes, mockFilterChain);

        verify(mockFilterChain).doFilter(mockReq, mockRes);
        verify(manager).authenticate(captor.capture());
        verify(SecurityContextHolder.getContext()).setAuthentication(authResult);
        assertThat(captor.getValue().getName()).isEqualTo("testJwt");

    }

    @Test
    public void doFilterInternalAuthenticateAnonymouslyIfNoAuthToken() throws ServletException, IOException {
        UsernamePasswordAuthenticationToken  authResult = 
            new UsernamePasswordAuthenticationToken("testUsername","testPass");
        given(manager.authenticate(any()))
            .willReturn(authResult);

        filter.doFilter(mockReq, mockRes, mockFilterChain);

        verify(mockFilterChain).doFilter(mockReq, mockRes);
        verify(SecurityContextHolder.getContext(), never()).setAuthentication(authResult);

    }

    @Test
    public void doFilterInternalCallsauthenticationEntryPointIfTokenIsInvalid() throws ServletException, IOException {
        mockReq.addHeader("XX-AUTH-XX", "testJwt");
        AuthenticationException ae = new BadCredentialsException("Invalid token.");
        given(manager.authenticate(any()))
            .willThrow(ae);

        filter.doFilter(mockReq, mockRes, mockFilterChain);

        verify(appAuthenticationEntryPoint).commence(mockReq, mockRes, ae);
        
    }
}
