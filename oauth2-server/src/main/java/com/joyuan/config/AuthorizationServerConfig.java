package com.joyuan.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import sun.security.util.SecurityConstants;

/**
 *
@EnableAuthorizationServer 开启了:
 * AuthorizationEndpoint=/oauth/authorize 获取授权服务
 * TokenEndpoint=/oauth/token 获取令牌token

几种授权类型（Grant Type）:
    authorization_code：授权码类型。
    implicit：隐式授权类型。
    password：资源所有者（即用户）密码类型。
    client_credentials：客户端凭据（客户端ID以及Key）类型。
    refresh_token：通过以上授权获得的刷新令牌来获取新的令牌。

ClientDetailsServiceConfigurer: 配置客户端信息(ClientDetailsService)如:id,secret,scopes,GrantType
    InMemoryClientDetailsService: 内存方式存储
    JdbcClientDetailsService: jdbc方式存储
    RedisTokenStore: redis
    JwtTokenStore: jwt

AuthorizationServerSecurityConfigurer:
    配置令牌端点(Token Endpoint)的安全约束

AuthorizationServerEndpointsConfigurer:
    用来配置授权（authorization）以及令牌（token）的访问端点和令牌服务(token services)
 */

//配置授权服务
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    //认证管理器
    @Autowired
    AuthenticationManager authenticationManager;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                .tokenKeyAccess("permitAll()") //url:/oauth/token_key,exposes public key for token verification if using JWT tokens
                .checkTokenAccess("isAuthenticated()") //url:/oauth/check_token allow check token
                .allowFormAuthenticationForClients(); //url中有client_id和client_secret的会走ClientCredentialsTokenEndpointFilter来保护
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        //配置了两个客户端,存储在内存中,也可以使用JdbcClientDetailsServiceBuilder存储到数据库
        clients.inMemory().withClient("client") //client_id
                .secret("client") //client_secret
                //授权类型
                .authorizedGrantTypes("password","authorization_code","refresh_token","client_credentials")
                .scopes("client")
                .redirectUris("http://www.baidu.com").autoApprove(true)
                .and()

                .withClient("client2") //client_id
                .secret("client2") //client_secret
                //授权类型
                .authorizedGrantTypes("password","authorization_code","refresh_token","client_credentials")
                .scopes("client2")
                .redirectUris("http://www.baidu.com").autoApprove(true);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .tokenStore(new InMemoryTokenStore()) //内存方式存储token
                .authenticationManager(authenticationManager); //管理认证管理器
    }
}
