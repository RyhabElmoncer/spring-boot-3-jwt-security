package com.RyhabExemple.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static com.RyhabExemple.security.user.Permission.*;
import static com.RyhabExemple.security.user.Role.*;
import static org.springframework.http.HttpMethod.*;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfiguration {

    // URLs accessibles sans authentification
    private static final String[] WHITE_LIST_URL = {
            "/api/v1/auth/**",
            "/v2/api-docs",
            "/v3/api-docs",
            "/v3/api-docs/**",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui/**",
            "/webjars/**",
            "/swagger-ui.html"
    };

    // Filtres et gestionnaires de sécurité
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Désactive la protection CSRF (Cross-Site Request Forgery)
                .csrf(AbstractHttpConfigurer::disable)
                // Configure les règles d'autorisation des requêtes
                .authorizeHttpRequests(req ->
                        req
                                // Autorise l'accès sans authentification aux URLs spécifiées
                                .requestMatchers(WHITE_LIST_URL).permitAll()
                                // Autorise l'accès aux gestionnaires pour les rôles ADMIN et MANAGER
                                .requestMatchers("/api/v1/management/**").hasAnyRole(ADMIN.name(), MANAGER.name())
                                // Autorise l'accès en lecture aux gestionnaires avec les permissions ADMIN_READ et MANAGER_READ
                                .requestMatchers(GET, "/api/v1/management/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
                                // Autorise l'accès en écriture aux gestionnaires avec les permissions ADMIN_CREATE et MANAGER_CREATE
                                .requestMatchers(POST, "/api/v1/management/**").hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
                                // Autorise l'accès en mise à jour aux gestionnaires avec les permissions ADMIN_UPDATE et MANAGER_UPDATE
                                .requestMatchers(PUT, "/api/v1/management/**").hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
                                // Autorise l'accès en suppression aux gestionnaires avec les permissions ADMIN_DELETE et MANAGER_DELETE
                                .requestMatchers(DELETE, "/api/v1/management/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())
                                // Toute autre requête doit être authentifiée
                                .anyRequest().authenticated()
                )
                // Configure la gestion de session à STATELESS (sans état)
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
                // Configure le fournisseur d'authentification
                .authenticationProvider(authenticationProvider)
                // Ajoute le filtre JWT avant le filtre d'authentification UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                // Configure la gestion de la déconnexion
                .logout(logout ->
                        logout
                                // URL de déconnexion
                                .logoutUrl("/api/v1/auth/logout")
                                // Gestionnaire de déconnexion personnalisé
                                .addLogoutHandler(logoutHandler)
                                // Action à réaliser en cas de succès de la déconnexion
                                .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext())
                );

        return http.build();
    }
}
