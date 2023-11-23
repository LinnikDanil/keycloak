package com.example.keycloak.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class TokenStoreService {

    private final StringRedisTemplate redisTemplate;
    private static final long TOKEN_TTL = 30; // TTL для токена, например, 30 минут

    public void storeToken(String userId, String token) {
        String tokenKey = "token:" + token;
        redisTemplate.opsForValue().set(tokenKey, "", TOKEN_TTL, TimeUnit.MINUTES);

        redisTemplate.opsForSet().add("user_tokens:" + userId, token);
    }

    public boolean isTokenValid(String token) {
        String tokenKey = "token:" + token;
        Boolean result = redisTemplate.hasKey(tokenKey);
        return result != null && result;
    }

    public void revokeToken(String token) {
        String tokenKey = "token:" + token;
        String userId = redisTemplate.opsForValue().get(tokenKey);
        redisTemplate.delete(tokenKey);

        if (userId != null) {
            redisTemplate.opsForSet().remove("user_tokens:" + userId, token);
        }
    }

    public void updateTokens(String userId, String newAccessToken, String newRefreshToken) {
        // Получение и удаление старых токенов пользователя
        Set<String> oldTokens = redisTemplate.opsForSet().members("user_tokens:" + userId);
        if (oldTokens != null) {
            oldTokens.forEach(this::revokeToken);
        }

        // Сохранение новых токенов
        storeToken(userId, newAccessToken);
        storeToken(userId, newRefreshToken);
    }

    public void revokeAllTokens(String userId) {
        Set<String> tokens = redisTemplate.opsForSet().members("user_tokens:" + userId);
        if (tokens != null) {
            tokens.forEach(this::revokeToken);
        }
        redisTemplate.delete("user_tokens:" + userId); // Удаление ключа множества токенов пользователя
    }
}
