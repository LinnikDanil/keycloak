package com.example.keycloak.keycloak.model;

import lombok.AccessLevel;
import lombok.Data;
import lombok.experimental.FieldDefaults;

/**
 * Класс для хранения данных токенов пользователя.
 */
@Data
@FieldDefaults(level = AccessLevel.PRIVATE)
public class TokenData {
    String userId;
    String accessToken;
    String refreshToken;
    String role;
    String fullName;
}