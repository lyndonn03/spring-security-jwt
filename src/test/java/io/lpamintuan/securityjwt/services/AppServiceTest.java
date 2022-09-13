package io.lpamintuan.securityjwt.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import io.lpamintuan.securityjwt.components.JwtsBuilder;
import io.lpamintuan.securityjwt.controllers.templates.AuthenticationTemplate;
import io.lpamintuan.securityjwt.models.UserInfo;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.BDDMockito.*;

import java.util.HashSet;

@ExtendWith(MockitoExtension.class)
public class AppServiceTest {

    private AppService appService;

    @Mock
    private UserDetailsService userDetailsService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtsBuilder jwtsBuilder;

    @BeforeEach
    public void setUpEeachTest() {
        this.appService = new AppService(userDetailsService, passwordEncoder, jwtsBuilder);
    }

    @Test
    public void getUserInfoShouldReturnUserInfoSuccessfullyIfUserIsInDB() {

        UserDetails user = new User("testUsername", "pass", new HashSet<>());
        given(userDetailsService.loadUserByUsername(anyString()))
            .willReturn((User)user);

        UserInfo result = appService.getUserInfo("testUsername");

        assertThat(result.getUsername()).isEqualTo(user.getUsername());
        verify(userDetailsService).loadUserByUsername(anyString());
        
    }

    @Test
    public void getUserInfoThrowsExceptionIfNotFound() {

        given(userDetailsService.loadUserByUsername(anyString()))
            .willThrow(new UsernameNotFoundException("not found."));

        assertThatThrownBy(() -> appService.getUserInfo("testUsername"))
            .isInstanceOf(UsernameNotFoundException.class)
            .hasMessage("not found.");

        verify(userDetailsService).loadUserByUsername("testUsername");

    }

    @Test
    public void signinUserReturnsTokenWhenSuccessful() {
        UserDetails user = new UserInfo("testUsername", "pass");
        given(userDetailsService.loadUserByUsername(anyString()))
            .willReturn(user);
        given(passwordEncoder.matches(any(), any()))
            .willReturn(true);
        given(jwtsBuilder.generate(user.getUsername()))
            .willReturn("sampleToken");

        String result = appService.signinUser(new AuthenticationTemplate("testUsername", "testPass"));

        assertThat(result).isNotNull();
        assertThat(result).isEqualTo("sampleToken");
        verify(userDetailsService).loadUserByUsername("testUsername");
        verify(jwtsBuilder).generate("testUsername");

    }

    @Test
    public void signinUserThrowsExceptionWhenPasswordNotValid() {
        UserDetails user = new UserInfo("testUsername", "pass");
        AuthenticationTemplate creds = new AuthenticationTemplate("testUsername", "pass");
        given(userDetailsService.loadUserByUsername(anyString()))
            .willReturn(user);
        given(passwordEncoder.matches(any(), any()))
            .willReturn(false);
        ArgumentCaptor<String> userPasswordCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> credPasswordCaptor = ArgumentCaptor.forClass(String.class);

        assertThatThrownBy(() -> appService.signinUser(creds))
            .isInstanceOf(BadCredentialsException.class)
            .hasMessageContaining("Invalid credentials");

        verify(passwordEncoder).matches(credPasswordCaptor.capture(), userPasswordCaptor.capture());
        assertThat(credPasswordCaptor.getValue()).isEqualTo(creds.getPassword());
        assertThat(userPasswordCaptor.getValue()).isEqualTo(user.getPassword());
        
    }

}
