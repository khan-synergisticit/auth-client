package com.americanworx.authclient.client;



import com.americanworx.authclient.config.Constants;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;

@Component
public class OAuthClient {
    private static final String url = "http://localhost:8040";

    public ResponseEntity<?> getAccessToken(String code) throws JsonProcessingException {
        String encodedCredentials = Base64.getEncoder().encodeToString(Constants.CLIENT_CREDENTIALS.getBytes());
        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();

        headers.add("Authorization", "Basic " + encodedCredentials);
        headers.add("Content-Type", "application/x-www-form-urlencoded");

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "client_credentials");
        map.add("code",code);
        map.add("redirect_uri","http://localhost:8080/index.html");
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        ResponseEntity<Object> response = restTemplate.exchange(Constants.OAUTH_TOKEN_URL, HttpMethod.POST, request, Object.class);
        Object body = response.getBody();


        ObjectMapper mapper = new ObjectMapper();
        JsonNode node = mapper.convertValue(body, JsonNode.class);

        String accessToken = node.get("access_token").asText();
        System.out.println("Access token: " + accessToken);
        return new ResponseEntity<>(node, HttpStatus.OK);
    }
}
