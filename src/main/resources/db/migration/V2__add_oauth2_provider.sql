-- Ajout du support OAuth2 sur la table users

-- 1. Rendre password_hash nullable (les users Google n'ont pas de mot de passe)
ALTER TABLE users
    ALTER COLUMN password_hash DROP NOT NULL;

-- 2. Ajouter la colonne provider (LOCAL par défaut pour tous les users existants)
ALTER TABLE users
    ADD COLUMN provider VARCHAR(20) NOT NULL DEFAULT 'LOCAL';

-- 3. Ajouter la colonne provider_id (sub Google)
ALTER TABLE users
    ADD COLUMN provider_id VARCHAR(100);

-- 4. Index composite pour retrouver rapidement un user OAuth2 par provider + provider_id
CREATE INDEX idx_user_provider ON users (provider, provider_id);

-- 5. Contrainte unique : un même compte Google ne peut pas être lié à deux users
CREATE UNIQUE INDEX uk_users_provider_provider_id
    ON users (provider, provider_id)
    WHERE provider_id IS NOT NULL;