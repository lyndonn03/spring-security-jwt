package io.lpamintuan.securityjwt.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

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

    

}
