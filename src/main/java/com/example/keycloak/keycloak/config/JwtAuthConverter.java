package com.example.keycloak.keycloak.config;

import com.example.keycloak.keycloak.service.TokenStoreService;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Конвертер для преобразования JWT в Authentication Token с учетом ролей и валидности.
 */
@Component
@RequiredArgsConstructor
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
    private final TokenStoreService tokenStoreService;

    @Value("${jwt.auth.converter.principle-attribute}")
    private String principleAttribute;

    @Value("${jwt.auth.converter.resource-id}")
    private String resourceId;

    /**
     * Конвертирует JWT в Authentication Token, проверяя его валидность и извлекая роли.
     *
     * @param jwt JWT для конвертации.
     * @return Сформированный Authentication Token.
     */
    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
        String token = jwt.getTokenValue();
        if (!tokenStoreService.isTokenValid(token)) {
            throw new InvalidTokenException("Token is invalid or has been revoked");
        }

        Collection<GrantedAuthority> authorities = Stream.concat(
                        jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                        extractResourceRoles(jwt).stream()
                )
                .collect(Collectors.toSet());

        return new JwtAuthenticationToken(jwt, authorities, getPrincipleClaimName(jwt));
    }

    /**
     * Получает имя принципала из JWT.
     *
     * @param jwt JWT, из которого извлекается принципал.
     * @return Имя принципала.
     */
    private String getPrincipleClaimName(Jwt jwt) {
        return principleAttribute != null ? principleAttribute : JwtClaimNames.SUB;
    }

    /**
     * Извлекает роли из JWT.
     *
     * @param jwt JWT для извлечения ролей.
     * @return Коллекция GrantedAuthority на основе ролей в JWT.
     */
    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new HashSet<>();

        // Извлечение клиентских ролей
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess != null) {
            Map<String, Object> resource = (Map<String, Object>) resourceAccess.getOrDefault(resourceId, Collections.emptyMap());
            Collection<String> resourceRoles = (Collection<String>) resource.getOrDefault("roles", Collections.emptyList());
            resourceRoles.forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
        }

        // Извлечение реалмовских ролей
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        if (realmAccess != null) {
            Collection<String> realmRoles = (Collection<String>) realmAccess.getOrDefault("roles", Collections.emptyList());
            realmRoles.forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
        }

        return authorities;
    }
}