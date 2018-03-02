package com.joyuan.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    //模拟用户,内存中存储,替换到容器中默认的UserDetailsService
    @Bean
    protected UserDetailsService userDetailsService(){
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("123").password("123").authorities("USER").build());
        manager.createUser(User.withUsername("1234").password("1234").authorities("USER").build());
        return manager;
    }
    //主要配置和资源相关,js,css,绕过了spring security的所有filter
    @Override
    public void configure(WebSecurity web) throws Exception {
//        web.ignoring().antMatchers("/webjars/**", "/images/**","/resources/**");
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatchers().antMatchers("/oauth/**","/public/**","/login/**") //默认匹配任何路径,添加匹配指定的路径
                .and()
                .authorizeRequests().antMatchers("/public/**").permitAll()//不拦截该地址
                .and()
                .authorizeRequests().antMatchers("/oauth/**").authenticated() //需要保护
                .and()
                .formLogin().and().httpBasic().disable();
    }
    //认证管理器
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
