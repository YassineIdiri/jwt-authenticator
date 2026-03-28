CREATE TABLE oauth2_pending_tokens (
    id         BIGSERIAL PRIMARY KEY,
    code       VARCHAR(36)  NOT NULL,
    user_id    BIGINT       NOT NULL,
    expires_at TIMESTAMP    NOT NULL,

    CONSTRAINT uk_oauth2_pending_code UNIQUE (code),
    CONSTRAINT fk_oauth2_pending_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_oauth2_pending_code    ON oauth2_pending_tokens (code);
CREATE INDEX idx_oauth2_pending_expires ON oauth2_pending_tokens (expires_at);