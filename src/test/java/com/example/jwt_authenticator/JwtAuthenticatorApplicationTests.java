package com.example.jwt_authenticator;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@ActiveProfiles("test")
class JwtAuthenticatorApplicationTests extends AbstractIntegrationTest {

    @Test
    void contextLoads() {
        // Vérifie juste que le contexte Spring démarre sans erreur
    }
}