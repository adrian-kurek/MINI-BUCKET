CREATE TABLE IF NOT EXISTS bucket_permissions (
    id SERIAL PRIMARY KEY,
    bucket_id INTEGER NOT NULL CONSTRAINT fk_bucket
        REFERENCES buckets (id)
        ON DELETE CASCADE,
    user_id INTEGER NOT NULL CONSTRAINT fk_user
        REFERENCES users (id)
        ON DELETE CASCADE,
    permission VARCHAR(16) NOT NULL CHECK (permission IN ('read', 'write', 'admin')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (bucket_id, user_id)
);