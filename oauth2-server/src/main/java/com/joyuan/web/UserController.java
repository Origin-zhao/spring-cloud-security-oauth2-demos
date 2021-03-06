package com.joyuan.web;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    @RequestMapping("/private/name")
    public String getName(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication.getName();
    }
    @RequestMapping("/public/name")
    public String getName2(){
        return "hello2";
    }
}
