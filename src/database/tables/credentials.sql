CREATE TABLE auth_service.credentials (
    user_id UUID PRIMARY KEY REFERENCES auth_service.users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT now()
);