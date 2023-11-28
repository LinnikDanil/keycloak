package com.example.keycloak.keycloak.controller;

import com.example.keycloak.keycloak.model.UserRegistrationDto;
import com.example.keycloak.keycloak.service.KeycloakAdminService;
import com.example.keycloak.user.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
@Slf4j
public class AdminController {

    private final KeycloakAdminService keycloakAdminService;
    private final UserService userService; // Сервис для работы с пользователями

    public AdminController(KeycloakAdminService keycloakAdminService, UserService userService) {
        this.keycloakAdminService = keycloakAdminService;
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody UserRegistrationDto userDto) {

        log.info("ADMIN CONTROLLER: REGISTER");

        // Создание пользователя в Keycloak
        keycloakAdminService.createUserInKeycloak(userDto);

        // Сохранение данных пользователя в базе данных
        //userService.createUser(userDto);

        return ResponseEntity.ok("User registered successfully");
    }
}
