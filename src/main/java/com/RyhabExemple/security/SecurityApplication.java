package com.RyhabExemple.security;

import com.RyhabExemple.security.auth.AuthenticationService;
import com.RyhabExemple.security.auth.RegisterRequest;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.RyhabExemple.security.user.Role.ADMIN;
import static com.RyhabExemple.security.user.Role.MANAGER;

@SpringBootApplication
public class SecurityApplication {


	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}


	@Bean
	public CommandLineRunner commandLineRunner(AuthenticationService service) {
		return args -> {
			// Création de la requête d'enregistrement pour un utilisateur administrateur
			var admin = RegisterRequest.builder()
					.firstname("Admin")
					.lastname("Admin")
					.email("admin@mail.com")
					.password("password")
					.role(ADMIN)
					.build();

			// Enregistrement de l'utilisateur administrateur et affichage du token d'accès
			System.out.println("Admin token: " + service.register(admin).getAccessToken());

			// Création de la requête d'enregistrement pour un utilisateur manager
			var manager = RegisterRequest.builder()
					.firstname("Admin")
					.lastname("Admin")
					.email("manager@mail.com")
					.password("password")
					.role(MANAGER)
					.build();

			// Enregistrement de l'utilisateur manager et affichage du token d'accès
			System.out.println("Manager token: " + service.register(manager).getAccessToken());
		};
	}
}
