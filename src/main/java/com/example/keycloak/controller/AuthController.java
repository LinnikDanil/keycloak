package com.example.keycloak.controller;

import com.example.keycloak.service.AuthService;
import com.example.keycloak.service.TokenData;
import com.example.keycloak.service.TokenStoreService;
import com.example.keycloak.util.TokenUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final TokenStoreService tokenStoreService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {
        log.info("CONTROLLER: LOGIN");

        TokenData tokenData = authService.login(username, password);

        if (tokenData == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Login failed");
        }

        // Используем метод updateTokens при входе в систему
        tokenStoreService.updateTokens(tokenData.getUserId(), tokenData.getAccessToken(), tokenData.getRefreshToken());
        return ResponseEntity.ok().body(tokenData);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestParam String refreshToken, @RequestParam String userId) {
        log.info("CONTROLLER: LOGOUT");

        if (!tokenStoreService.isTokenValid(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired token");
        }

        // Предполагаем, что refreshToken содержит информацию о userId
        tokenStoreService.revokeAllTokens(userId);
        authService.logout(refreshToken); // Если это необходимо для вашей логики с Keycloak

        return ResponseEntity.ok().build();
    }

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

        // Используем метод updateTokens для обновления токенов
        tokenStoreService.updateTokens(newTokenData.getUserId(), newTokenData.getAccessToken(), newTokenData.getRefreshToken());

        return ResponseEntity.ok().body(newTokenData);
    }
}
