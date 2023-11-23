package com.example.keycloak.controller;

import com.example.keycloak.service.AuthService;
import com.example.keycloak.service.TokenData;
import com.example.keycloak.service.TokenStoreService;
import com.example.keycloak.util.TokenUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Контроллер для аутентификации пользователя.
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final TokenStoreService tokenStoreService;

    /**
     * Вход в систему с использованием имени пользователя и пароля.
     *
     * @param username Имя пользователя.
     * @param password Пароль.
     * @return Ответ с данными токена или сообщение об ошибке.
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {
        log.info("CONTROLLER: LOGIN");

        TokenData tokenData = authService.login(username, password);
        if (tokenData == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Login failed");
        }

        tokenStoreService.updateTokens(tokenData.getUserId(), tokenData.getAccessToken(), tokenData.getRefreshToken());
        return ResponseEntity.ok().body(tokenData);
    }

    /**
     * Выход из системы с инвалидацией всех токенов пользователя.
     *
     * @param refreshToken Refresh токен пользователя.
     * @param userId       Идентификатор пользователя.
     * @return Пустой ответ, подтверждающий успешный выход из системы.
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestParam String refreshToken, @RequestParam String userId) {
        log.info("CONTROLLER: LOGOUT");

        String userIdInToken = TokenUtils.extractUserIdFromRefreshToken(refreshToken);

        if (!tokenStoreService.isTokenValid(refreshToken) || !userId.equals(userIdInToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired token");
        }

        tokenStoreService.revokeAllTokens(userId);
        authService.logout(refreshToken);

        return ResponseEntity.ok().build();
    }

    /**
     * Обновление токенов пользователя.
     *
     * @param refreshToken Существующий refresh токен для обновления.
     * @return Новый набор токенов или сообщение об ошибке.
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshAuthToken(@RequestParam String refreshToken) {
        log.info("CONTROLLER: REFRESH");

        if (!tokenStoreService.isTokenValid(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        }

        TokenData newTokenData = authService.refreshToken(refreshToken);
        if (newTokenData == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Failed to refresh token");
        }

        tokenStoreService.updateTokens(newTokenData.getUserId(), newTokenData.getAccessToken(), newTokenData.getRefreshToken());
        return ResponseEntity.ok().body(newTokenData);
    }
}