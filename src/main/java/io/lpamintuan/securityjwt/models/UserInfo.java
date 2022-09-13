package io.lpamintuan.securityjwt.models;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserInfo implements UserDetails {

    private String username;

    @JsonIgnore
    private String password;

    @Getter(AccessLevel.NONE)
    private Boolean isAccountNonExpired;

    private Boolean isAccountNonLocked;
    private Boolean isCredentialsNonExpired;
    private Boolean isEnabled;
    private Set<GrantedAuthority> authorities;

    public UserInfo(String username, String password) {
        this.username = username;
        this.password = password;
        this.isAccountNonExpired = true;
        this.isAccountNonLocked = true;
        this.isCredentialsNonExpired = true;
        this.isEnabled = true;
        this.authorities = new HashSet<>();
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @JsonGetter("isAccountNonExpired")
    @Override
    public boolean isAccountNonExpired() {
        return this.isAccountNonExpired;
    }

    @JsonGetter("isAccountNonLocked")
    @Override
    public boolean isAccountNonLocked() {
        return this.isAccountNonLocked;
    }

    @JsonGetter("isCredentialsNonExpired")
    @Override
    public boolean isCredentialsNonExpired() {
        return this.isCredentialsNonExpired;
    }

    @JsonGetter("isEnabled")
    @Override
    public boolean isEnabled() {
        return this.isEnabled;
    }

    public void addRole(GrantedAuthority authority) {
        this.authorities.add(authority);
    }
    
}
