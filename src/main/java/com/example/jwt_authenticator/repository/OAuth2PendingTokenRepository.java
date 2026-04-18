package com.example.jwt_authenticator.repository;

import com.example.jwt_authenticator.entity.OAuth2PendingToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDateTime;
import java.util.Optional;

public interface OAuth2PendingTokenRepository extends JpaRepository<OAuth2PendingToken, Long> {

    Optional<OAuth2PendingToken> findByCode(String code);

    // Nettoyage des codes expirés (appelé par le scheduler)
    @Modifying
    @Query("DELETE FROM OAuth2PendingToken t WHERE t.expiresAt < :threshold")
    int deleteExpiredTokens(LocalDateTime threshold);
}