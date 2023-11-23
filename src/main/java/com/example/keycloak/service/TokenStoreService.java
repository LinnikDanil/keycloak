package com.example.keycloak.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Сервис для управления токенами, хранящимися в Redis.
 */
@Service
@RequiredArgsConstructor
public class TokenStoreService {

    private static final long ACCESS_TOKEN_TTL = 30; // TTL для access токена, 30 минут
    private static final long REFRESH_TOKEN_TTL = 43200; // TTL для refresh токена, 30 дней (43200 минут)
    private final StringRedisTemplate redisTemplate;

    /**
     * Сохраняет токен пользователя в Redis с установкой соответствующего времени жизни.
     *
     * @param userId        Идентификатор пользователя.
     * @param token         Токен для сохранения.
     * @param isAccessToken Флаг, указывающий, является ли токен access токеном.
     */
    public void storeToken(String userId, String token, boolean isAccessToken) {
        String tokenKey = "token:" + token;
        long ttl = isAccessToken ? ACCESS_TOKEN_TTL : REFRESH_TOKEN_TTL;
        redisTemplate.opsForValue().set(tokenKey, userId, ttl, TimeUnit.MINUTES);
        redisTemplate.opsForSet().add("user_tokens:" + userId, token);
    }

    /**
     * Проверяет валидность токена.
     *
     * @param token Токен для проверки.
     * @return true, если токен действителен.
     */
    public boolean isTokenValid(String token) {
        String tokenKey = "token:" + token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(tokenKey));
    }

    /**
     * Отзывает токен пользователя.
     *
     * @param token Токен для отзыва.
     */
    public void revokeToken(String token) {
        String tokenKey = "token:" + token;
        String userId = redisTemplate.opsForValue().get(tokenKey);
        redisTemplate.delete(tokenKey);

        if (userId != null) {
            redisTemplate.opsForSet().remove("user_tokens:" + userId, token);
        }
    }

    /**
     * Обновляет токены пользователя, заменяя старые на новые.
     *
     * @param userId          Идентификатор пользователя.
     * @param newAccessToken  Новый access токен.
     * @param newRefreshToken Новый refresh токен.
     */
    public void updateTokens(String userId, String newAccessToken, String newRefreshToken) {
        Set<String> oldTokens = redisTemplate.opsForSet().members("user_tokens:" + userId);
        if (oldTokens != null) {
            oldTokens.forEach(this::revokeToken);
        }

        storeToken(userId, newAccessToken, true);
        storeToken(userId, newRefreshToken, false);
    }

    /**
     * Отзывает все токены пользователя.
     *
     * @param userId Идентификатор пользователя для отзыва всех токенов.
     */
    public void revokeAllTokens(String userId) {
        Set<String> tokens = redisTemplate.opsForSet().members("user_tokens:" + userId);
        if (tokens != null) {
            tokens.forEach(this::revokeToken);
        }
        redisTemplate.delete("user_tokens:" + userId);
    }
}