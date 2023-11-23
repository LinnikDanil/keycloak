package com.example.keycloak.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.experimental.UtilityClass;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.Map;

/**
 * Утилитный класс для работы с JWT токенами.
 */
@UtilityClass
public class TokenUtils {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /**
     * Извлекает идентификатор пользователя из refresh токена.
     *
     * @param refreshToken Refresh токен, из которого нужно извлечь идентификатор пользователя.
     * @return Идентификатор пользователя или null, если токен недействителен или возникла ошибка.
     */
    public static String extractUserIdFromRefreshToken(String refreshToken) {
        if (!StringUtils.hasText(refreshToken)) {
            return null;
        }

        try {
            String[] parts = refreshToken.split("\\.");
            if (parts.length != 3) {
                return null; // Неверный формат токена
            }

            String payload = new String(Base64.decodeBase64(parts[1]));
            Map<String, String> payloadMap = OBJECT_MAPPER.readValue(payload, new TypeReference<>() {
            });

            return payloadMap.get("sub");
        } catch (IOException e) {
            e.printStackTrace();
            return null; // Ошибка при декодировании или чтении JSON
        }
    }
}