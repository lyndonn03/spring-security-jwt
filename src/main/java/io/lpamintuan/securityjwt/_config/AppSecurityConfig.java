package io.lpamintuan.securityjwt._config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;

import io.lpamintuan.securityjwt.models.UserInfo;

@Configuration
public class AppSecurityConfig {

    @Autowired
    private AuthenticationEntryPoint authenticationEntryPoint;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                .mvcMatchers(HttpMethod.GET, "/userinfo").authenticated()
                .mvcMatchers("/error").permitAll();

        http.exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint);

        return http.build();

    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    UserDetailsService userDetailsService() {

        UserInfo user1 = UserInfo.builder()
                .username("user1")
                .password("pass1")
                .build();
        UserInfo user2 = UserInfo.builder()
                .username("user2")
                .password("pass2")
                .build();

        user1.addRole(new SimpleGrantedAuthority("ROLE_USER"));
        user2.addRole(new SimpleGrantedAuthority("ROLE_ADMIN"));

        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(user1);
        manager.createUser(user2);

        return manager;
    }

}
