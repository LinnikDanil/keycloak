package com.example.keycloak.keycloak.model;

import lombok.AccessLevel;
import lombok.Data;
import lombok.experimental.FieldDefaults;

@Data
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserRegistrationDto {
    String username;
    String password;
    String role;
    String name;
    String secondName;
}
