package com.americanworx.authclient.config;

import com.americanworx.authclient.client.UserClient;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.io.IOException;
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

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuer;

    @Bean
    SecurityFilterChain securityFilterChain (HttpSecurity http) throws Exception {

         http
                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
                    authorizationManagerRequestMatcherRegistry
                          .requestMatchers( "/save", "/getAccessToken").permitAll()
                            .anyRequest().authenticated();

                })

                .oauth2Login(login -> login.successHandler(successHandler))
                 .oauth2Client(code -> code.authorizationCodeGrant(codeGrant ->codeGrant.accessTokenResponseClient(accessTokenResponseClient())))
                .logout(logout -> logout.permitAll().logoutSuccessHandler(oidcLogoutSuccessHandler()).clearAuthentication(true).deleteCookies().invalidateHttpSession(true));
         http
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
                Map<String, Object> obj = new HashMap<>();
                RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
                if(accessToken != null) {

                    Cookie cookie = new Cookie("access_token", accessToken.getTokenValue());
                    cookie.setDomain("192.168.1.69");
                    cookie.setHttpOnly(false);
                    response.addCookie(cookie);
                    System.out.println("cookie: " + accessToken.getTokenValue() + ", referrer: " + request.getRequestURI() + " , 1: " + request.getHeader(HttpHeaders.REFERER));

                    redirectStrategy.sendRedirect(request, response, Constants.SHOP_URL + ":8080/?code=" + accessToken.getTokenValue());
                    //redirectStrategy.sendRedirect(request, response, Constants.SHOP_URL + ":8080/user");
                }
            ObjectMapper mapper = new ObjectMapper();
            obj.put("access_token", accessToken.getTokenValue());
            JsonNode node = mapper.convertValue(obj, JsonNode.class);
            userClient.sendUser(obj, Constants.SHOP_URL + ":8080/api/user");
            }
        };


    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withIssuerLocation(issuer).build();
    }
    OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        SecurityContextHolder.getContext().setAuthentication(null);
        successHandler.setPostLogoutRedirectUri("{baseUrl}");
        return successHandler;
    }

    @Bean
    DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient(){
        return new DefaultAuthorizationCodeTokenResponseClient();
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

//        @Bean
//    public ClientRegistrationRepository clientRegistrationRepository() {
//        return new InMemoryClientRegistrationRepository(this.googleClientRegistration());
//    }
//    private ClientRegistration googleClientRegistration() {
//        return ClientRegistration.withRegistrationId("shopping")
//                .clientId("shopping")
//                .clientSecret("donkey")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
//                .scope("openid", "profile", "read", "write")
//                .authorizationUri("http://localhost:8040/oauth2/authorize")
//               .tokenUri("http://localhost:8040/oauth2/v1/token")
////                .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
////                .userNameAttributeName(IdTokenClaimNames.SUB)
////                .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
//                .clientName("Google")
//                .build();
//    }
//    private ClientRegistration googleClientRegistration() {
//        return ClientRegistration.withRegistrationId("google")
//                .clientId("google-client-id")
//                .clientSecret("google-client-secret")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
//                .scope("openid", "profile", "email", "address", "phone")
//                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
//                .tokenUri("https://www.googleapis.com/oauth2/v4/token")
//                .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
//                .userNameAttributeName(IdTokenClaimNames.SUB)
//                .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
//                .clientName("Google")
//                .build();
//    }
}
