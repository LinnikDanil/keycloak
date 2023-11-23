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

/**
 * Сервис для взаимодействия с Keycloak для аутентификации и управления токенами.
 */
@Service
public class AuthService {
    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();
    @Value("${keycloak.auth-server-url}")
    private String serverUrl;
    @Value("${keycloak.realm}")
    private String realm;
    @Value("${keycloak.resource}")
    private String clientId;

    /**
     * Аутентификация пользователя и получение токенов.
     *
     * @param username Имя пользователя.
     * @param password Пароль.
     * @return Данные токена или null при ошибке аутентификации.
     */
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
            return null;
        }
    }

    /**
     * Выход пользователя из системы и инвалидация refresh токена.
     *
     * @param refreshToken Refresh токен, который необходимо инвалидировать.
     */
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

    /**
     * Обновление access токена пользователя с использованием refresh токена.
     *
     * @param refreshToken Используемый для обновления refresh токен.
     * @return Обновленные данные токена или null при ошибке.
     */
    public TokenData refreshToken(String refreshToken) {
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

    /**
     * Извлечение данных токена из JSON ответа.
     *
     * @param responseBody Ответ сервера аутентификации в формате JSON.
     * @return Данные токена.
     */
    private TokenData extractTokenData(String responseBody) {
        try {
            Map<String, Object> responseMap = objectMapper.readValue(responseBody, new TypeReference<>() {
            });
            TokenData tokenData = new TokenData();
            tokenData.setAccessToken((String) responseMap.get("access_token"));
            tokenData.setRefreshToken((String) responseMap.get("refresh_token"));

            // Декодирование JWT и извлечение идентификатора пользователя и ролей
            String accessToken = tokenData.getAccessToken();
            String[] parts = accessToken.split("\\.");
            if (parts.length == 3) {
                String payload = new String(Base64.decodeBase64(parts[1]));
                Map<String, Object> payloadMap = objectMapper.readValue(payload, new TypeReference<>() {
                });

                String userId = (String) payloadMap.get("sub");
                tokenData.setUserId(userId);

                Map<String, List<String>> realmAccess = (Map<String, List<String>>) payloadMap.get("realm_access");
                List<String> roles = realmAccess != null ? realmAccess.get("roles") : Collections.emptyList();
                tokenData.setRole(roles.isEmpty() ? null : roles.get(0));
            }

            return tokenData;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}