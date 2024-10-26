package com.americanworx.authclient.controller.app;

import com.americanworx.authclient.client.OAuthClient;

import com.americanworx.authclient.client.UserClient;
import com.americanworx.authclient.config.Constants;
import com.americanworx.authclient.domain.token.Token;
import com.americanworx.authclient.domain.user.User;
import com.americanworx.authclient.service.app.AppService;
import com.americanworx.authclient.service.user.UserService;
import com.fasterxml.jackson.core.JsonProcessingException;


import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RestController
@CrossOrigin(origins = Constants.SHOP_URL + ":8080")
public class AppController {
    @Autowired
    private AppService appService;

    @Autowired
    private UserService userService;

    @Autowired
    private UserClient userClient;

    @Autowired
    private OAuthClient oAuthClient;

    @GetMapping
    public ResponseEntity<String> getPublicData() {
        return ResponseEntity.ok("Public Data");
    }


    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public void oauthLogin() {
       Token token =  appService.getJwtToken();
    }

    @RequestMapping(value = "/login?", method = RequestMethod.GET)
    void handleFoo(HttpServletResponse response) throws IOException {
        response.sendRedirect("/login");
    }

    @RequestMapping(value = "/getAccessToken", method = RequestMethod.GET)
    public ResponseEntity<?> getAccessToken(@RequestParam String code) throws  IOException{
        var authentication = SecurityContextHolder.getContext().getAuthentication();
//        System.out.println("Authentication: " + authentication.toString());
        return oAuthClient.getAccessToken(code);
    }


    @RequestMapping(value = "/test", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> test(@RequestBody JsonNode node) throws  IOException{
        System.out.println("Code: " + node.toString());
        return new ResponseEntity<>(node, HttpStatus.OK);
    }

    @RequestMapping(value = "/save", method = {RequestMethod.POST, RequestMethod.GET}, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> createUser(@RequestBody JsonNode json) throws JsonProcessingException {
        System.out.println("User: " + json.toString());
        User user = new User();
        user.setName(json.get("name").asText());
        user.setEmail(json.get("email").asText());
        user.setMobileNumber(json.get("mobileNumber").asText());
        user.setAddress(json.get("address").asText());
        user.setCity(json.get("city").asText());
        user.setState(json.get("state").asText());
        user.setProfileImage(json.get("img").asText());
        user.setPincode(json.get("pincode").asText());
        user.setRole("ROLE_USER");

        Map<String, String> map = new HashMap<>();
        map.put("email", user.getEmail());
        map.put("password", json.get("pass").asText());
        map.put("role", user.getRole());
        ObjectMapper mapper = new ObjectMapper();
        JsonNode node = mapper.convertValue(map, JsonNode.class);
        JsonNode userNode = userClient.createUser(node).getBody();
        if(userNode != null) {
            Integer userId = userNode.get("id").asInt();
            System.out.println("id: " + userId);
            user.setId(userId);
            User savedUser = userService.createUser(user);;
            return ResponseEntity.ok(savedUser);
        } else {
            return new ResponseEntity<>("Unable to create user.", HttpStatus.BAD_REQUEST);
        }

    }
    public record LoginRequest(String username, String password) {}
}
