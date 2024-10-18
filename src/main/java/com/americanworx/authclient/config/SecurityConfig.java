package com.americanworx.authclient.config;

import com.americanworx.authclient.service.app.AppService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;
    @Autowired
    private OAuth2AuthorizedClientManager authorizedClientManager;

    @Autowired
    private AppService appService;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuer;

    @Bean
    SecurityFilterChain securityFilterChain (HttpSecurity http) throws Exception {

         http
                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
                    authorizationManagerRequestMatcherRegistry
                          .requestMatchers( "/save").permitAll()
                            .anyRequest().authenticated();
                })
                .oauth2Login(login -> login.successHandler(successHandler))
                 .oauth2Client(code -> code.authorizationCodeGrant(codeGrant ->codeGrant.accessTokenResponseClient(accessTokenResponseClient())))
                .logout(logout -> logout.logoutSuccessHandler(oidcLogoutSuccessHandler()).clearAuthentication(true).deleteCookies().invalidateHttpSession(true));
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

                RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

                if(accessToken != null) {
                    System.out.println("AT: " + accessToken.getTokenValue());
                    redirectStrategy.sendRedirect(request, response, Constants.SHOP_URL + ":8080?access_token=" + accessToken.getTokenValue());
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
                ccfg.setAllowedOrigins(List.of("http://192.168.1.243:8080"));
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
