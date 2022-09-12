package io.lpamintuan.securityjwt.controllers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import io.lpamintuan.securityjwt._config.AppAuthenticationEntryPoint;
import io.lpamintuan.securityjwt._config.AppSecurityConfig;
import io.lpamintuan.securityjwt.models.UserInfo;
import io.lpamintuan.securityjwt.services.AppService;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import static org.mockito.BDDMockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.*;

@WebMvcTest(AppController.class)
@Import({ AppSecurityConfig.class, AppAuthenticationEntryPoint.class })
public class AppControllerTest {

    @Autowired
    private WebApplicationContext ctx;

    private MockMvc mockMvc;

    @MockBean
    private AppService appService;

    @BeforeEach
    public void setUpEachTest() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(ctx)
                .apply(springSecurity())
                .build();
    }

    @Test
    @WithMockUser(username = "test", authorities = "USER")
    public void userinfoRouteSuccessfullyCalled() throws Exception {

        mockMvc.perform(get("/userinfo")
                .contentType(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "testUsername")
    public void userinfoRouteSuccessfullyReturnedUserInfo() throws Exception {
        UserInfo user = UserInfo.builder()
                .username("testUsername")
                .isAccountNonExpired(true)
                .build();
        given(appService.getUserInfo(anyString())).willReturn(user);

        mockMvc.perform(get("/userinfo")
                .contentType(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.username").value("testUsername"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.isAccountNonExpired").value(true))
                .andExpect(jsonPath("$.accountNonExpired").doesNotExist());

        verify(appService).getUserInfo("testUsername");

    }

    @Test
    @WithMockUser(username = "testUsername")
    public void userinfoRouteReturnsErrorIfNoUserInfoFound() throws Exception {
        given(appService.getUserInfo(anyString()))
                .willThrow(new UsernameNotFoundException("Invalid user."));

        mockMvc.perform(get("/userinfo"))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.content").value("Invalid user."))
                .andExpect(jsonPath("$.path").value("/userinfo"));
               
        verify(appService).getUserInfo("testUsername");

    }

    @Test
    @WithAnonymousUser
    public void userinfoRouteReturnsUnauthorizedWhenNotAuthenticated() throws Exception {

        mockMvc.perform(get("/userinfo")
                .contentType(MediaType.APPLICATION_JSON_VALUE))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(status().isUnauthorized());

    }

}
