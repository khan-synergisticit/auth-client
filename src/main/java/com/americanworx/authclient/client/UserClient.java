package com.americanworx.authclient.client;

import com.americanworx.authclient.config.Constants;
import com.americanworx.authclient.domain.user.User;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.Map;

@Component
public class UserClient {
    private static final String url = Constants.AUTH_SERVER_URL+":8040";

    public ResponseEntity<JsonNode> createUser(JsonNode node) throws JsonProcessingException {
        System.out.println("client: " + node.toString());
        String encodedCredentials = Base64.getEncoder().encodeToString(Constants.CLIENT_CREDENTIALS.getBytes());
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
//        headers.add("Authorization", "Basic " + encodedCredentials);
        headers.add("Content-Type", "application/json");
        HttpEntity<String> request = new HttpEntity<>(node.toString(), headers);
        ResponseEntity<Object> response = restTemplate.exchange(url + "/user/save", HttpMethod.POST, request, Object.class);
        Object body = response.getBody();
        if(body != null) {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode node1 = mapper.convertValue(body, JsonNode.class);
            return new ResponseEntity<>(node1, HttpStatus.OK);
        }
        else {
            return new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
        }
    }

    public void sendUser(User user, String url) throws JsonProcessingException {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("user", user.toString());
        System.out.println("node: " + user.toString());
        HttpEntity<User> request = new HttpEntity<>(headers);
        RestTemplate restTemplate = new RestTemplate();
        Object res = restTemplate.postForEntity(url, request, String.class);
        System.out.println("response: " + res.toString());
    }

}
