package com.americanworx.authclient.controller.user;

import com.americanworx.authclient.config.Constants;
import com.americanworx.authclient.domain.token.Token;
import com.americanworx.authclient.domain.user.User;
import com.americanworx.authclient.service.app.AppService;
import com.americanworx.authclient.service.user.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/user")
@CrossOrigin(origins = Constants.SHOP_URL + ":8080")
public class UserController {

    @Autowired private UserService userService;
    @Autowired private AppService appService;

    @RequestMapping(value = "/find", method = RequestMethod.GET)
    public ResponseEntity<?> getUserData() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        String name = authentication.getName();
        System.out.println("name: " + name);
        User user = userService.getUserByEmail(name);
        if(user != null) {
            Token token =  new Token();
            OAuth2AccessToken accessToken = appService.getAccessToken(authentication);
            OAuth2RefreshToken refreshToken = appService.getRefreshToken(authentication);
            if(accessToken != null && refreshToken != null) {
                token.setAccessToken(accessToken.toString());
                token.setRefreshToken(appService.getRefreshToken(authentication).toString());
                user.setToken(token);
            }
            return ResponseEntity.ok(user);
        }else {
            return new ResponseEntity<>(name, HttpStatus.NOT_FOUND);
        }
    }
}
