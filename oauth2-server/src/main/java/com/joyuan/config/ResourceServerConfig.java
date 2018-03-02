package com.joyuan.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;

/**
 * 资源服务器,负责拦截 需要OAuth授权才能访问的资源地址
 */
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter{
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        super.configure(resources);
    }
    @Override
    public void configure(HttpSecurity http) throws Exception {
        //private开头的地址需要OAuth授权才能访问的资源地址
        http.authorizeRequests().antMatchers("/private/**").authenticated();
    }
}
