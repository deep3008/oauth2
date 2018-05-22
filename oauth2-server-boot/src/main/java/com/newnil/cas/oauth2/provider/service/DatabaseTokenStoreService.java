//package com.newnil.cas.oauth2.provider.service;
//
//import com.newnil.cas.oauth2.provider.dao.entity.AccessTokenEntity;
//import com.newnil.cas.oauth2.provider.dao.entity.RefreshTokenEntity;
//import com.newnil.cas.oauth2.provider.dao.repository.AccessTokenRepository;
//import com.newnil.cas.oauth2.provider.dao.repository.RefreshTokenRepository;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.oauth2.common.OAuth2AccessToken;
//import org.springframework.security.oauth2.common.OAuth2RefreshToken;
//import org.springframework.security.oauth2.provider.OAuth2Authentication;
//import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
//import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
//import org.springframework.security.oauth2.provider.token.TokenStore;
//import org.springframework.stereotype.Service;
//import org.springframework.transaction.annotation.Transactional;
//
//import java.util.Collection;
//import java.util.stream.Collectors;
//
//@Service
//@Transactional
//public class DatabaseTokenStoreService implements TokenStore {
//
//    @Autowired
//    private AccessTokenRepository accessTokenRepository;
//
//    @Autowired
//    private RefreshTokenRepository refreshTokenRepository;
//
//    private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();
//
//    @Override
//    public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
//        return readAuthentication(token.getValue());
//    }
//
//    @Override
//    public OAuth2Authentication readAuthentication(String token) {
//        return accessTokenRepository.findOneByTokenId(token).map(AccessTokenEntity::getAuthentication).orElse(null);
//    }
//
//    @Override
//    public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
//
//        String tokenId = token.getValue();
//
//        final RefreshTokenEntity refreshToken;
//        String authenticationKey = authenticationKeyGenerator.extractKey(authentication);
//
//        if (token.getRefreshToken() != null) {
//            refreshToken = refreshTokenRepository.findOneByTokenId(token.getRefreshToken().getValue()).orElseGet(
//                    () -> refreshTokenRepository.save(RefreshTokenEntity.builder()
//                            .tokenId(token.getRefreshToken().getValue())
//                            .token(token.getRefreshToken())
//                            .authentication(authentication)
//                            .build()));
//        } else {
//            refreshToken = null;
//        }
//
//        accessTokenRepository.findOneByAuthenticationId(authenticationKey).ifPresent(
//                accessTokenEntity -> {
//                    if (!tokenId.equals(accessTokenEntity.getTokenId())) {
//                        accessTokenRepository.delete(accessTokenEntity);
//                    }
//                }
//        );
//
//        AccessTokenEntity entityToSave = accessTokenRepository.findOneByTokenId(tokenId).map(accessTokenEntity -> {
//            accessTokenEntity.setToken(token);
//            accessTokenEntity.setAuthenticationId(authenticationKey);
//            accessTokenEntity.setAuthentication(authentication);
//            accessTokenEntity.setUserName(authentication.isClientOnly() ? null : authentication.getName());
//            accessTokenEntity.setClientId(authentication.getOAuth2Request().getClientId());
//            accessTokenEntity.setRefreshToken(refreshToken);
//            return accessTokenEntity;
//        }).orElseGet(() -> AccessTokenEntity.builder()
//                .tokenId(tokenId)
//                .token(token)
//                .authenticationId(authenticationKey)
//                .authentication(authentication)
//                .userName(authentication.isClientOnly() ? null : authentication.getName())
//                .clientId(authentication.getOAuth2Request().getClientId())
//                .refreshToken(refreshToken)
//                .build());
//
//        accessTokenRepository.save(entityToSave);
//    }
//
//    @Override
//    public OAuth2AccessToken readAccessToken(String tokenValue) {
//        return accessTokenRepository.findOneByTokenId(tokenValue).map(AccessTokenEntity::getToken).orElse(null);
//    }
//
//    @Override
//    public void removeAccessToken(OAuth2AccessToken token) {
//        accessTokenRepository.deleteByTokenId(token.getValue());
//    }
//
//    @Override
//    public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
//        RefreshTokenEntity entityToSave = refreshTokenRepository.findOneByTokenId(refreshToken.getValue()).map(refreshTokenEntity -> {
//            refreshTokenEntity.setToken(refreshToken);
//            refreshTokenEntity.setAuthentication(authentication);
//            return refreshTokenEntity;
//        }).orElseGet(() -> RefreshTokenEntity.builder().tokenId(refreshToken.getValue()).token(refreshToken).authentication(authentication).build());
//
//        refreshTokenRepository.save(entityToSave);
//    }
//
//    @Override
//    public OAuth2RefreshToken readRefreshToken(String tokenValue) {
//        return refreshTokenRepository.findOneByTokenId(tokenValue).map(RefreshTokenEntity::getToken).orElse(null);
//    }
//
//    @Override
//    public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
//        return refreshTokenRepository.findOneByTokenId(token.getValue()).map(RefreshTokenEntity::getAuthentication).orElse(null);
//    }
//
//    @Override
//    public void removeRefreshToken(OAuth2RefreshToken token) {
//        refreshTokenRepository.deleteByTokenId(token.getValue());
//    }
//
//    @Override
//    public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
//        accessTokenRepository.deleteByRefreshTokenTokenId(refreshToken.getValue());
//    }
//
//    @Override
//    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
//        String authenticationKey = authenticationKeyGenerator.extractKey(authentication);
//        return accessTokenRepository.findOneByAuthenticationId(authenticationKey).map(AccessTokenEntity::getToken).orElse(null);
//    }
//
//    @Override
//    public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
//        return accessTokenRepository.findAllByClientIdAndUserName(clientId, userName).stream().map(AccessTokenEntity::getToken).collect(Collectors.toList());
//    }
//
//    @Override
//    public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
//        return accessTokenRepository.findAllByClientId(clientId).stream().map(AccessTokenEntity::getToken).collect(Collectors.toList());
//    }
//}



package com.newnil.cas.oauth2.provider.service;

import com.newnil.cas.oauth2.provider.dao.entity.AccessTokenEntity;
import com.newnil.cas.oauth2.provider.dao.entity.RefreshTokenEntity;
import com.newnil.cas.oauth2.provider.dao.repository.AccessTokenRepository;
import com.newnil.cas.oauth2.provider.dao.repository.RefreshTokenRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

import java.util.Collection;
import java.util.stream.Collectors;

//@Service
//@Transactional
@Slf4j
public class DatabaseTokenStoreService implements TokenStore {

    private RedisTokenStore redisTokenStore;

    @Autowired
    private AccessTokenRepository accessTokenRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

    public void setRedisTokenStore(RedisTokenStore redisTokenStore) {
        this.redisTokenStore = redisTokenStore;
    }

    @Override
    public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
        return readAuthentication(token.getValue());
    }

    @Override
    public OAuth2Authentication readAuthentication(String token) {
        OAuth2Authentication oAuth2Authentication = redisTokenStore.readAuthentication(token);

        if (oAuth2Authentication != null) {
            log.info("readAuthentication in cache. authentication: {}", oAuth2Authentication);
            return oAuth2Authentication;
        }

        oAuth2Authentication = accessTokenRepository.findOneByTokenId(token).map(AccessTokenEntity::getAuthentication).orElse(null);
        log.info("readAuthentication in db. authentication: {}", oAuth2Authentication);

        return oAuth2Authentication;
    }

    @Override
    public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {

        String tokenId = token.getValue();

        final RefreshTokenEntity refreshToken;
        String authenticationKey = authenticationKeyGenerator.extractKey(authentication);

        if (token.getRefreshToken() != null) {
            refreshToken = refreshTokenRepository.findOneByTokenId(token.getRefreshToken().getValue()).orElseGet(
                    () -> refreshTokenRepository.save(RefreshTokenEntity.builder()
                            .tokenId(token.getRefreshToken().getValue())
                            .token(token.getRefreshToken())
                            .authentication(authentication)
                            .build()));
        } else {
            refreshToken = null;
        }

        accessTokenRepository.findOneByAuthenticationId(authenticationKey).ifPresent(
                accessTokenEntity -> {
                    if (!tokenId.equals(accessTokenEntity.getTokenId())) {
                        accessTokenRepository.delete(accessTokenEntity);
                    }
                }
        );

        AccessTokenEntity entityToSave = accessTokenRepository.findOneByTokenId(tokenId).map(accessTokenEntity -> {
            accessTokenEntity.setToken(token);
            accessTokenEntity.setAuthenticationId(authenticationKey);
            accessTokenEntity.setAuthentication(authentication);
            accessTokenEntity.setUserName(authentication.isClientOnly() ? null : authentication.getName());
            accessTokenEntity.setClientId(authentication.getOAuth2Request().getClientId());
            accessTokenEntity.setRefreshToken(refreshToken);
            return accessTokenEntity;
        }).orElseGet(() -> AccessTokenEntity.builder()
                .tokenId(tokenId)
                .token(token)
                .authenticationId(authenticationKey)
                .authentication(authentication)
                .userName(authentication.isClientOnly() ? null : authentication.getName())
                .clientId(authentication.getOAuth2Request().getClientId())
                .refreshToken(refreshToken)
                .build());

        accessTokenRepository.save(entityToSave);

        redisTokenStore.storeAccessToken(token, authentication);
    }

    @Override
    public OAuth2AccessToken readAccessToken(String tokenValue) {

        OAuth2AccessToken oAuth2AccessToken = redisTokenStore.readAccessToken(tokenValue);

        if (oAuth2AccessToken != null) {
            log.info("readAccessToken in cache. AccessToken: {}", oAuth2AccessToken);
            return oAuth2AccessToken;
        }

        oAuth2AccessToken = accessTokenRepository.findOneByTokenId(tokenValue).map(AccessTokenEntity::getToken).orElse(null);
        log.info("readAccessToken in db. AccessToken: {}", oAuth2AccessToken);

        return oAuth2AccessToken;
    }

    @Override
    public void removeAccessToken(OAuth2AccessToken token) {
        accessTokenRepository.deleteByTokenId(token.getValue());
        redisTokenStore.removeAccessToken(token);
    }

    @Override
    public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
        RefreshTokenEntity entityToSave = refreshTokenRepository.findOneByTokenId(refreshToken.getValue()).map(refreshTokenEntity -> {
            refreshTokenEntity.setToken(refreshToken);
            refreshTokenEntity.setAuthentication(authentication);
            return refreshTokenEntity;
        }).orElseGet(() -> RefreshTokenEntity.builder().tokenId(refreshToken.getValue()).token(refreshToken).authentication(authentication).build());

        refreshTokenRepository.save(entityToSave);

        redisTokenStore.storeRefreshToken(refreshToken, authentication);
    }

    @Override
    public OAuth2RefreshToken readRefreshToken(String tokenValue) {

        OAuth2RefreshToken oAuth2RefreshToken = redisTokenStore.readRefreshToken(tokenValue);
        if (oAuth2RefreshToken != null) {
            log.info("readRefreshToken in cache. RefreshToken: {}", oAuth2RefreshToken);
            return oAuth2RefreshToken;
        }

        oAuth2RefreshToken = refreshTokenRepository.findOneByTokenId(tokenValue).map(RefreshTokenEntity::getToken).orElse(null);
        log.info("readRefreshToken in db. RefreshToken: {}", oAuth2RefreshToken);

        return oAuth2RefreshToken;
    }

    @Override
    public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
        OAuth2Authentication oAuth2Authentication = redisTokenStore.readAuthenticationForRefreshToken(token);
        if (oAuth2Authentication != null) {
            log.info("readAuthenticationForRefreshToken in cache. OAuth2Authentication: {}", oAuth2Authentication);
            return oAuth2Authentication;
        }

        oAuth2Authentication = refreshTokenRepository.findOneByTokenId(token.getValue()).map(RefreshTokenEntity::getAuthentication).orElse(null);
        log.info("readAuthenticationForRefreshToken in db. OAuth2Authentication: {}", oAuth2Authentication);

        return oAuth2Authentication;
    }

    @Override
    public void removeRefreshToken(OAuth2RefreshToken token) {
        refreshTokenRepository.deleteByTokenId(token.getValue());

        redisTokenStore.removeRefreshToken(token);
    }

    @Override
    public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
        accessTokenRepository.deleteByRefreshTokenTokenId(refreshToken.getValue());

        redisTokenStore.removeAccessTokenUsingRefreshToken(refreshToken);
    }

    @Override
    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {

        OAuth2AccessToken accessToken = redisTokenStore.getAccessToken(authentication);

        if (accessToken != null) {
            log.info("getAccessToken in cache. AccessToken: {}", accessToken);
            return accessToken;
        }

        String authenticationKey = authenticationKeyGenerator.extractKey(authentication);
        accessToken = accessTokenRepository.findOneByAuthenticationId(authenticationKey).map(AccessTokenEntity::getToken).orElse(null);
        log.info("getAccessToken in db. AccessToken: {}", accessToken);

        return accessToken;
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {

        Collection<OAuth2AccessToken> clientIdAndUserName = redisTokenStore.findTokensByClientIdAndUserName(clientId, userName);
        if (clientIdAndUserName != null && !clientIdAndUserName.isEmpty()) {
            log.info("findTokensByClientIdAndUserName in cache. ClientIdAndUserName: {}", clientIdAndUserName);
            return clientIdAndUserName;
        }

        clientIdAndUserName = accessTokenRepository.findAllByClientIdAndUserName(clientId, userName).stream().map(AccessTokenEntity::getToken).collect(Collectors.toList());
        log.info("findTokensByClientIdAndUserName in db. ClientIdAndUserName: {}", clientIdAndUserName);

        return clientIdAndUserName;
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {

        Collection<OAuth2AccessToken> tokensByClientId = redisTokenStore.findTokensByClientId(clientId);
        if (tokensByClientId != null && !tokensByClientId.isEmpty()) {
            log.info("findTokensByClientId in cache. ClientId: {}", tokensByClientId);
            return tokensByClientId;
        }

        tokensByClientId = accessTokenRepository.findAllByClientId(clientId).stream().map(AccessTokenEntity::getToken).collect(Collectors.toList());
        log.info("findTokensByClientId in db. ClientId: {}", tokensByClientId);

        return tokensByClientId;
    }
}
