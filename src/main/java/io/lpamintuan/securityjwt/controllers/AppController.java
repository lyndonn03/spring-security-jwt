package io.lpamintuan.securityjwt.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.lpamintuan.securityjwt.controllers.templates.AuthenticationTemplate;
import io.lpamintuan.securityjwt.controllers.templates.TokenTemplate;
import io.lpamintuan.securityjwt.models.UserInfo;
import io.lpamintuan.securityjwt.services.AppService;

@RestController
public class AppController {

    @Autowired
    private AppService appService;

    @GetMapping("/userinfo")
    public ResponseEntity<UserInfo> userinfo(Authentication authentication) {
        UserInfo user = appService.getUserInfo(authentication.getName());
        return new ResponseEntity<>(user, HttpStatus.OK);
    }

    @PostMapping(path = "/signin", consumes = MediaType.APPLICATION_JSON_VALUE)
    public TokenTemplate signin(@RequestBody AuthenticationTemplate creds) {

        String token = appService.signinUser(creds);
        return new TokenTemplate(token);
    }

    

}
