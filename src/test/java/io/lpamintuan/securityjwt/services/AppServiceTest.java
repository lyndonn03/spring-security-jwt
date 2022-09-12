package io.lpamintuan.securityjwt.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import io.lpamintuan.securityjwt.models.UserInfo;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.BDDMockito.*;

@ExtendWith(MockitoExtension.class)
public class AppServiceTest {

    private AppService appService;

    @Mock
    private UserDetailsService userDetailsService;

    @BeforeEach
    public void setUpEeachTest() {
        this.appService = new AppService(userDetailsService);
    }

    @Test
    public void getUserInfoShouldReturnUserInfoSuccessfullyIfUserIsInDB() {

        UserInfo user = UserInfo.builder()
                            .username("testUsername")
                            .build();
        given(userDetailsService.loadUserByUsername(anyString()))
            .willReturn((UserDetails)user);

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
}
