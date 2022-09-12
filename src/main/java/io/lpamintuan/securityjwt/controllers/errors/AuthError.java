package io.lpamintuan.securityjwt.controllers.errors;

import java.time.LocalDateTime;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthError {

    private LocalDateTime timestamp;

    private int status;

    private String error;

    private String content;

    private String path;
    
}
