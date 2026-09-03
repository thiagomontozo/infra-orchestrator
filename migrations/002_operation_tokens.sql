ALTER TABLE operations ADD COLUMN IF NOT EXISTS auth_token_id text NOT NULL DEFAULT '';
