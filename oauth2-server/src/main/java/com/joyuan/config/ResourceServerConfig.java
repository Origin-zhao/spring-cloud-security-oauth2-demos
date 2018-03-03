package com.joyuan.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.util.Base64Utils;

import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateFactorySpi;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 资源服务器,负责拦截 需要OAuth授权才能访问的资源地址
 */
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter{

    public void configure(HttpSecurity http) throws Exception {
        //private开头的地址需要OAuth授权才能访问的资源地址
        http.authorizeRequests().antMatchers("/private/**").authenticated();
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer config) {
        config.tokenServices(tokenServices());
    }

    //JwtTokenStore关联转换器
    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    //转换器
    @Bean
    public JwtAccessTokenConverter accessTokenConverter()  {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setVerifierKey(getPublicKey());
        return converter;
    }

    //获取公钥字符串
    private String getPublicKey() {
        String publicKey= null;
        try {
            //公钥文件
            ClassPathResource resource = new ClassPathResource("publickey.cer");
            X509Certificate cer = X509Certificate.getInstance(resource.getInputStream());
            publicKey = "-----BEGIN PUBLIC KEY-----\n" +
                    Base64Utils.encodeToString(cer.getPublicKey().getEncoded()) +
                    "\n-----END PUBLIC KEY-----";
        }catch (Exception e){
            e.printStackTrace();
        }
        return publicKey;
    }

    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        //设置TokenStore,里面包含了JwtAccessTokenConverter转换器
        defaultTokenServices.setTokenStore(tokenStore());
        return defaultTokenServices;
    }
}
