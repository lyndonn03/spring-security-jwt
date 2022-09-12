package io.lpamintuan.securityjwt.controllers.templates;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthenticationTemplate {

    private String username;

    private String password;
    
}
