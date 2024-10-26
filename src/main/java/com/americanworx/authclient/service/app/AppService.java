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

@Service
public class AppService {


    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;
    @PreAuthorize("hasAuthority('SCOPE_read')")

    public Token getJwtToken(){

        var authentication = SecurityContextHolder.getContext().getAuthentication();
//        System.out.println("Authentication: " + authentication.toString());
        var accessToken = getAccessToken(authentication);
        var refreshToken = getRefreshToken(authentication);
        if(accessToken == null || refreshToken == null){
            return null;
        }else {
            Token token = new Token();
            token.setExpiresAt(accessToken.getExpiresAt());
            token.setAccessToken(accessToken.getTokenValue());
            token.setRefreshToken(refreshToken.getTokenValue());
            return token;
        }
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
