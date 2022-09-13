package io.lpamintuan.securityjwt._config;

import java.io.IOException;
import java.io.OutputStream;
import java.time.LocalDateTime;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.lpamintuan.securityjwt.controllers.errors.AuthError;

@Component
public class AppAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {

        LocalDateTime timestamp = LocalDateTime.now();
        int status = HttpStatus.BAD_REQUEST.value();
        String error = "Bad Request";
        String content = authException.getMessage();
        String path = request.getPathInfo();

        OutputStream out = response.getOutputStream();
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        out.write(mapper.writeValueAsString(new AuthError(timestamp, status, error, content, path)).getBytes());
        out.flush();

    }

}
