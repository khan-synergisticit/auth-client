package com.americanworx.authclient.controller.app;

import com.americanworx.authclient.client.OAuthClient;

import com.americanworx.authclient.config.Constants;
import com.americanworx.authclient.domain.user.User;
import com.americanworx.authclient.service.app.AppService;
import com.fasterxml.jackson.core.JsonProcessingException;


import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@CrossOrigin(origins = Constants.SHOP_URL)
public class AppController {
    @Autowired
    private AppService appService;

    @Autowired
    private OAuthClient oAuthClient;

    @GetMapping
    public ResponseEntity<String> getPublicData() {
        return ResponseEntity.ok("Public Data");
    }


    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public void oauthLogin(HttpServletRequest request, HttpServletResponse response) {
       User user=  appService.getJwtToken();

    }


    @RequestMapping(value = "/getAccessToken", method = RequestMethod.GET)
    public ResponseEntity<?> getAccessToken(@RequestParam String code) throws  IOException{
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("Authentication: " + authentication.toString());
        return oAuthClient.getAccessToken(code);
    }


    @RequestMapping(value = "/test", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> test(@RequestBody JsonNode node) throws  IOException{
        System.out.println("Code: " + node.toString());
        return new ResponseEntity<>(node, HttpStatus.OK);
    }
    public record LoginRequest(String username, String password) {}
}
