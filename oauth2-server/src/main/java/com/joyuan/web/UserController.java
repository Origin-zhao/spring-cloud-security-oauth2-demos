package com.joyuan.web;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    @RequestMapping("/private/name")
    public String getName(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication.toString();
    }

    @RequestMapping("/public/name")
    public String getName2(){
        return "hello2";
    }
}
