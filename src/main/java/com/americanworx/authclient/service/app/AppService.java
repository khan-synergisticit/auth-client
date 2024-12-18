package com.americanworx.authclient.service.app;

import com.americanworx.authclient.domain.token.Token;
import com.americanworx.authclient.domain.user.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class AppService {


    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;
    @PreAuthorize("hasAuthority('SCOPE_read')")

    public List<Token> getJwtToken(){

        var authentication = SecurityContextHolder.getContext().getAuthentication();
//        System.out.println("Authentication: " + authentication.toString());
        var accessToken = getAccessToken(authentication);
        var refreshToken = getRefreshToken(authentication);
        List<Token> tokens = new ArrayList<>();
        if(accessToken != null){
            Token token = new Token();
            token.setExpiresAt(accessToken.getExpiresAt());
            token.setTokenValue(accessToken.getTokenValue());
            token.setTokenType("access_token");
            tokens.add(token);
        }
        if(refreshToken != null){
            Token token = new Token();
            token.setExpiresAt(refreshToken.getExpiresAt());
            token.setTokenValue(refreshToken.getTokenValue());
            token.setTokenType("refresh_token");
            tokens.add(token);
        }

        return tokens;
    }

    public OAuth2AccessToken getAccessToken (Authentication authentication) {
        var authorizedClient = this.getAuthorizedClient(authentication);
        if (authorizedClient != null) {
            OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
            if (accessToken != null) {
                return accessToken;
            }
        }
        return null;
    }

    public OAuth2RefreshToken getRefreshToken(Authentication authentication) {
        var authorizedClient = this.getAuthorizedClient(authentication);
        if (authorizedClient != null) {
            OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
            if (refreshToken != null) {
                return refreshToken;
            }
        }
        return null;
    }

    private OAuth2AuthorizedClient getAuthorizedClient(Authentication authentication) {
        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            String clientRegistrationId = oauthToken.getAuthorizedClientRegistrationId();
            String principalName = oauthToken.getName();
            return authorizedClientService
                    .loadAuthorizedClient(clientRegistrationId, principalName);
        }
        return null;
    }
}
