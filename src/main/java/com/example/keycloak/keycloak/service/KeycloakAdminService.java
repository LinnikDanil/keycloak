package com.example.keycloak.keycloak.service;

import com.example.keycloak.keycloak.model.UserRegistrationDto;
import jakarta.ws.rs.core.Response;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class KeycloakAdminService {
    @Value("${keycloak.auth-server-url}")
    private String serverUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.admin-client.client-id}")
    private String clientId;

//    @Value("${keycloak-admin-client.client-secret}")
//    private String clientSecret;

    public void createUserInKeycloak(UserRegistrationDto userDto) {
        Keycloak keycloak = KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm(realm)
                .clientId(clientId)
                //.clientSecret(clientSecret)
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .build();

        UserRepresentation user = new UserRepresentation();
        user.setUsername(userDto.getUsername());
        user.setEnabled(true);

        // Установка атрибутов пользователя, если требуется
        Map<String, List<String>> attributes = new HashMap<>();
        // Здесь добавьте дополнительные атрибуты
        user.setAttributes(attributes);

        // Установка пароля
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(userDto.getPassword());
        credential.setTemporary(false);

        // Установка ролей, если требуется
        // ...

        Response response = keycloak.realm(realm).users().create(user);
        if (response.getStatus() != Response.Status.CREATED.getStatusCode()) {
            throw new RuntimeException("Failed to create user in Keycloak");
        }

        String userId = getCreatedId(response);

        // Установка пароля пользователя
        UserResource userResource = keycloak.realm(realm).users().get(userId);
        userResource.resetPassword(credential);

        // Установка ролей пользователя
        // ...

        keycloak.close();
    }

    private String getCreatedId(Response response) {
        URI location = response.getLocation();
        if (location == null) return null;
        String path = location.getPath();
        return path.substring(path.lastIndexOf('/') + 1);
    }
}
