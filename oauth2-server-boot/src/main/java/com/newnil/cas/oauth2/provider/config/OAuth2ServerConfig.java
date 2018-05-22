package com.newnil.cas.oauth2.provider.config;

import com.newnil.cas.oauth2.provider.service.OAuth2DatabaseClientDetailsService;
import lombok.extern.slf4j.Slf4j;
import org.joda.time.DateTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * 填坑注意：
 * <p>
 * OAuthProvider不可以和OAuthClient在同一个contextPath下（即使是不同端口也不行，
 * 不要问我为什么会知道）。否则会发生意料不到难以想象甚至你调查不出的错误。
 * https://github.com/spring-projects/spring-security-oauth/issues/322#issuecomment-
 * 64951927
 */
@Slf4j
@Configuration
@EnableAuthorizationServer
public class OAuth2ServerConfig extends AuthorizationServerConfigurerAdapter {

//    @Autowired
//    private DatabaseTokenStoreService tokenStoreService;

    @Autowired
    private OAuth2DatabaseClientDetailsService oAuth2DatabaseClientDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

    @Bean
    public RedisTokenStore redisTokenStore() {
        return new RedisTokenStore(redisConnectionFactory);
    }

    @Bean
    public ApprovalStore approvalStore() {
        TokenApprovalStore tokenStore = new TokenApprovalStore();
        tokenStore.setTokenStore(redisTokenStore());
        return tokenStore;
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints)
            throws Exception {
        // 配置授权endpoint
//        tokenStoreService.setRedisTokenStore(new RedisTokenStore(redisConnectionFactory));

        // tokenStore改由redis保存
        endpoints.tokenStore(redisTokenStore()).approvalStore(approvalStore())
        .authenticationManager(authenticationManager);

        // add by Deep
        endpoints.accessTokenConverter(accessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter() {

            @Override
            public Map<String, ?> convertAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {

                User user = (User) authentication.getUserAuthentication().getPrincipal();
                log.info("Deep Principal: {}", user);

                final Map<String, Object> additionalInformation = new HashMap<>();
                Date expireTime = DateTime.now().plusSeconds(60 * 10).toDate();
                additionalInformation.put("expire", expireTime);
                additionalInformation.put("userName", user.getUsername());

                ((DefaultOAuth2AccessToken)token).setAdditionalInformation(additionalInformation);

                return super.convertAccessToken(token, authentication);
            }
        };

        accessTokenConverter.setSigningKey("sss");

        return accessTokenConverter;

    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security)
            throws Exception {
        // 配置授权endpoint权限
        security.checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(oAuth2DatabaseClientDetailsService);
    }

}
