package com.americanworx.authclient.config;

import com.americanworx.authclient.client.OAuthClient;
import com.americanworx.authclient.client.UserClient;
import com.americanworx.authclient.domain.token.Token;
import jakarta.servlet.ServletException;


import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;

import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;


import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;
    @Autowired
    private OAuth2AuthorizedClientManager authorizedClientManager;
    @Autowired
    private UserClient userClient;

    @Autowired private OAuthClient oAuthClient;
    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuer;

    @Bean
    SecurityFilterChain securityFilterChain (HttpSecurity http) throws Exception {
//        http.sessionManagement( sess -> sess.sessionCreationPolicy(
//            SessionCreationPolicy.ALWAYS
//        ))
//                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
//                    authorizationManagerRequestMatcherRegistry
//                            .requestMatchers( "/save", "/getAccessToken").permitAll()
//                            .anyRequest().authenticated();
//
//                })

         http
                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
                    authorizationManagerRequestMatcherRegistry
                          .requestMatchers( "/save", "/getAccessToken").permitAll()
                            .anyRequest().authenticated();

                })
                .oauth2Login(login -> login.successHandler(successHandler))
                 .logout(logout -> logout.logoutSuccessHandler(oidcLogoutSuccessHandler()).clearAuthentication(true).deleteCookies().invalidateHttpSession(true).permitAll())
                 .oidcLogout(logout -> logout.backChannel(Customizer.withDefaults()))
                //.oidcLogout(logout -> logout.backChannel(Customizer.withDefaults()))
                .oauth2Client(code -> code.authorizationCodeGrant(codeGrant ->codeGrant.accessTokenResponseClient(accessTokenResponseClient())))
                .cors(cors->cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt->jwt.decoder(jwtDecoder())));

         return http.build();
    }

        AuthenticationSuccessHandler successHandler = new AuthenticationSuccessHandler() {

        @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

            OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("shopping")
                        .principal(authentication)
                        .attributes(attrs -> {
                            attrs.put(HttpServletRequest.class.getName(), request);
                            attrs.put(HttpServletResponse.class.getName(), response);
                        })
                        .build();
                OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);
                assert authorizedClient != null;
                OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
                RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
                if(accessToken != null) {
                    Token token = new Token();
                    token.setTokenValue(accessToken.getTokenValue());
                    token.setTokenType("access_token");
                    token.setExpiresAt(accessToken.getExpiresAt());
                    userClient.sendUser(token, Constants.SHOP_URL + ":8080/api/user");

                    Cookie cookie = new Cookie("token", token.getTokenValue());
                    cookie.setDomain(Constants.SHOP_URL_BASE);
                    cookie.setPath("/");
                    cookie.setHttpOnly(true);
                    Duration duration = Duration.between(Instant.now(), accessToken.getExpiresAt() );
                    cookie.setMaxAge(duration.toSecondsPart());
                    cookie.setSecure(true);
                    response.addCookie(cookie);
                    System.out.println("cookie: " + cookie.getValue());
                    response.sendRedirect(Constants.SHOP_URL + ":8080/loggedIn");
//                    redirectStrategy.sendRedirect(request, response, Constants.SHOP_URL + ":8080");

                }

            }
        };


    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withIssuerLocation(issuer).build();
    }


    OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        SecurityContextHolder.getContext().setAuthentication(null);

        successHandler.setPostLogoutRedirectUri(Constants.SHOP_URL + ":8080/loggedOut");
        System.out.println("Logout success");
        return successHandler;
    }

    @Bean
    DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient(){
        DefaultAuthorizationCodeTokenResponseClient responseClient = new DefaultAuthorizationCodeTokenResponseClient();
        return responseClient;
    }

    private CorsConfigurationSource corsConfigurationSource() {
        return new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration ccfg = new CorsConfiguration();
                ccfg.setAllowedOrigins(List.of(Constants.SHOP_URL + ":8080"));
                ccfg.setAllowedMethods(Collections.singletonList("*"));
                ccfg.setAllowCredentials(true);
                ccfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PUT","OPTIONS","PATCH", "DELETE"));
                ccfg.setAllowedHeaders(Collections.singletonList("*"));
                ccfg.setExposedHeaders(List.of("Authorization"));
                ccfg.setMaxAge(7200L);
                return ccfg;
            }
        };

    }

}
