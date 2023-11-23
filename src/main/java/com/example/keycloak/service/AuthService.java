package com.example.keycloak.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Service
public class AuthService {
    @Value("${keycloak.auth-server-url}")
    private String serverUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.resource}")
    private String clientId;

    private final RestTemplate restTemplate = new RestTemplate();

    public TokenData login(String username, String password) {
        String endpoint = serverUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", clientId);
        map.add("username", username);
        map.add("password", password);
        map.add("grant_type", "password");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(endpoint, request, String.class);
            return extractTokenData(response.getBody());
        } catch (HttpClientErrorException e) {
            e.printStackTrace();
            // Обработка ошибки, например, неверные учетные данные
            return null;
        }
    }

    public void logout(String refreshToken) {
        String endpoint = serverUrl + "/realms/" + realm + "/protocol/openid-connect/logout";

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", clientId);
        map.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        restTemplate.postForEntity(endpoint, request, String.class);
    }

    public TokenData refreshToken(String refreshToken) {
        // URL для запроса на обновление токена в Keycloak
        String endpoint = serverUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", clientId);
        map.add("refresh_token", refreshToken);
        map.add("grant_type", "refresh_token");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(endpoint, request, String.class);
            return extractTokenData(response.getBody());
        } catch (HttpClientErrorException e) {
            e.printStackTrace();
            return null;
        }
    }

    private TokenData extractTokenData(String responseBody) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> responseMap = mapper.readValue(responseBody, new TypeReference<Map<String, Object>>() {
            });
            TokenData tokenData = new TokenData();
            tokenData.setAccessToken((String) responseMap.get("access_token"));
            tokenData.setRefreshToken((String) responseMap.get("refresh_token"));

            // Декодирование JWT и извлечение ролей
            String accessToken = (String) responseMap.get("access_token");
            String[] parts = accessToken.split("\\."); // Разделение токена на части
            if (parts.length == 3) {
                String payload = new String(Base64.decodeBase64(parts[1]));
                Map<String, Object> payloadMap = mapper.readValue(payload, new TypeReference<Map<String, Object>>() {
                });

                String userId = (String) payloadMap.get("sub");
                tokenData.setUserId(userId);

                // Логика извлечения ролей из payloadMap, например, из payloadMap.get("realm_access")
                Map<String, List<String>> realmAccess = (Map<String, List<String>>) payloadMap.get("realm_access");
                List<String> roles = realmAccess.get("roles");
                tokenData.setRole(roles != null && !roles.isEmpty() ? roles.get(0) : null); // Пример для одной роли
            }

            return tokenData;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}
