package com.example.keycloak.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.experimental.UtilityClass;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import java.util.Base64;
import java.util.Map;

@UtilityClass
public class TokenUtils {

    public static String extractUserIdFromRefreshToken(String refreshToken) {
        if (!StringUtils.hasText(refreshToken)) {
            return null;
        }

        try {
            String[] parts = refreshToken.split("\\.");
            if (parts.length != 3) {
                return null; // Неверный формат токена
            }

            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            Map<String, String> payloadMap = new ObjectMapper().readValue(payload, new TypeReference<>() {});

            return payloadMap.get("sub");
        } catch (Exception e) {
            e.printStackTrace();
            return null; // Ошибка при декодировании или чтении JSON
        }
    }
}