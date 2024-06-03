package com.RyhabExemple.security.config;

import com.RyhabExemple.security.auditing.ApplicationAuditAware;
import com.RyhabExemple.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Configuration de l'application pour la gestion de la sécurité et des utilisateurs.
 */
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

  private final UserRepository repository;

  /**
   * Définit le service de récupération des détails de l'utilisateur.
   * Utilisé pour charger les détails de l'utilisateur à partir du dépôt d'utilisateurs en fonction de l'email.
   *
   * @return une implémentation de UserDetailsService
   */
  @Bean
  public UserDetailsService userDetailsService() {
    return username -> repository.findByEmail(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
  }

  /**
   * Configure le fournisseur d'authentification pour l'application.
   * Utilise un DaoAuthenticationProvider pour l'authentification basée sur les détails de l'utilisateur et le mot de passe.
   *
   * @return une instance d'AuthenticationProvider
   */
  @Bean
  public AuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailsService());
    authProvider.setPasswordEncoder(passwordEncoder());
    return authProvider;
  }

  /**
   * Configure l'audit de l'application.
   * Utilisé pour fournir des informations sur l'utilisateur actuellement authentifié pour l'audit.
   *
   * @return une instance d'ApplicationAuditAware
   */
  @Bean
  public ApplicationAuditAware auditorAware() {
    return new ApplicationAuditAware();
  }

  /**
   * Fournit le gestionnaire d'authentification.
   * Utilise la configuration d'authentification pour créer et configurer le gestionnaire d'authentification.
   *
   * @param config la configuration d'authentification
   * @return une instance d'AuthenticationManager
   * @throws Exception si une erreur survient lors de la création du gestionnaire d'authentification
   */
  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    return config.getAuthenticationManager();
  }

  /**
   * Fournit un encodeur de mots de passe.
   * Utilise BCrypt pour encoder les mots de passe.
   *
   * @return une instance de PasswordEncoder
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
