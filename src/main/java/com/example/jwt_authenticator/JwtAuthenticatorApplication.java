package com.example.jwt_authenticator;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan("com.example.jwt_authenticator.config.properties")
public class JwtAuthenticatorApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtAuthenticatorApplication.class, args);
	}

}
