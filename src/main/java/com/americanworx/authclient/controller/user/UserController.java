package com.americanworx.authclient.controller.user;

import com.americanworx.authclient.client.UserClient;
import com.americanworx.authclient.config.Constants;
import com.americanworx.authclient.domain.user.User;
import com.americanworx.authclient.service.user.UserService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/user")
@CrossOrigin(origins = Constants.SHOP_URL)
public class UserController {

    @Autowired private UserService userService;


    @RequestMapping(value = "/find", method = RequestMethod.GET)
    public ResponseEntity<?> getUserData() {
        String name = SecurityContextHolder.getContext().getAuthentication().getName();
        System.out.println("name: " + name);
        User user = userService.getUserByEmail(name);
        if(user != null) {
            return ResponseEntity.ok(user);
        }else {
            return new ResponseEntity<>(name, HttpStatus.NOT_FOUND);
        }
//        String authorization = request.getHeader("Authorization");
//        authorization = authorization.substring(7);
//        Jwt jwt = jwtDecoder.decode(authorization);
//        System.out.println("Authorization: " + jwt.getClaims());
//        RestTemplate restTemplate1 = new RestTemplate();
//        HttpHeaders headers1 = new HttpHeaders();
//        headers1.add("Authorization", "Bearer " + authorization);
//        headers1.add("Content-Type", "application/x-www-form-urlencoded");
//        HttpEntity<MultiValueMap<String, String>> request1 = new HttpEntity<>(headers1);
//        ResponseEntity<Object> response2 = restTemplate1.exchange("http://localhost:8040/userinfo", HttpMethod.GET, request1, Object.class);
//        Object body2 = response2.getBody();
//        ObjectMapper mapper = new ObjectMapper();
//        JsonNode node2 = mapper.convertValue(body2, JsonNode.class);
//        System.out.println(node2.toString());

//        User user = userService.getUserByEmail(email);
//        if(user != null) {
//            return ResponseEntity.ok(user);
//        } else {
//            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
//        }
    }
}
