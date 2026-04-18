package com.example.jwt_authenticator.entity;

import com.example.jwt_authenticator.dto.Role;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "users",
        indexes = {
                @Index(name = "idx_user_username", columnList = "username"),
                @Index(name = "idx_user_email",    columnList = "email"),
                @Index(name = "idx_user_provider", columnList = "provider, provider_id")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String username;

    @Column(nullable = false, unique = true, length = 150)
    private String email;

    // ✅ nullable — les users Google n'ont pas de mot de passe
    @Column(name = "password_hash", length = 255)
    private String passwordHash;

    // ✅ Champs e-commerce
    @Column(name = "first_name", length = 100)
    private String firstName;

    @Column(name = "last_name", length = 100)
    private String lastName;

    @Column(name = "phone", length = 20)
    private String phone;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private Role role;

    // ✅ BOTH = compte local + Google liés
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private AuthProvider provider = AuthProvider.LOCAL;

    @Column(name = "provider_id", length = 100)
    private String providerId;

    @Column(nullable = false)
    private boolean active = true;

    @Column(nullable = false)
    private boolean locked = false;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;
    private LocalDateTime lastLoginAt;

    @PrePersist
    protected void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    public void markLoggedIn() {
        this.lastLoginAt = LocalDateTime.now();
    }

    public boolean isAccountUsable() {
        return active && !locked;
    }

    // ✅ True seulement si AUCUN password → pas de login classique possible
    public boolean isOAuthUser() {
        return provider == AuthProvider.GOOGLE;
    }

    // ✅ Nouveau — le compte supporte-t-il le login par password ?
    public boolean supportsPasswordLogin() {
        return provider == AuthProvider.LOCAL || provider == AuthProvider.BOTH;
    }

    // ✅ Nouveau — le compte supporte-t-il le login Google ?
    public boolean supportsGoogleLogin() {
        return provider == AuthProvider.GOOGLE || provider == AuthProvider.BOTH;
    }
}