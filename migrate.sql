-- Migration: Create auth_service table
ALTER TABLE auth_service ADD COLUMN IF NOT EXISTS service TEXT;
CREATE TABLE IF NOT EXISTS auth_service (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES public.user(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key TEXT NOT NULL,
    service TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_auth_service_user_id ON auth_service(user_id); 