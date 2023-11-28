package com.example.keycloak.keycloak.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // Включает поддержку безопасности веб-секьюрити Spring.
@EnableGlobalMethodSecurity(prePostEnabled = true) // Позволяет использовать аннотации безопасности на методах.
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthConverter jwtAuthConverter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // Настройка HTTP Security
        http
                .cors(AbstractHttpConfigurer::disable)
                // Отключение CSRF (Cross-Site Request Forgery) защиты для Stateless-сессий
                .csrf(AbstractHttpConfigurer::disable)
                // Настройка правил авторизации запросов
                .authorizeHttpRequests(configurer ->
                        configurer
                                .requestMatchers("/auth/**", "/demo/unauthorized").permitAll() // Разрешение всех запросов к "/auth/**"
                                .anyRequest().authenticated() // Все остальные запросы должны быть аутентифицированы
                );

        // Настройка OAuth 2.0 Resource Server
        http
                .oauth2ResourceServer(oauth2ResourceServer ->
                        oauth2ResourceServer.jwt()
                                .jwtAuthenticationConverter(jwtAuthConverter) // Использование кастомного конвертера для JWT
                );

        // Установка политики управления сессией как STATELESS,
        // что означает, что приложение не будет создавать и использовать сессии
        http
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        return http.build();
    }
}
