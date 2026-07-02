-- Add user_metadata column to users table
-- This allows storing additional user information as JSONB

ALTER TABLE public.users 
ADD COLUMN IF NOT EXISTS user_metadata jsonb DEFAULT '{}'::jsonb;

-- Add index for better query performance on user_metadata
CREATE INDEX IF NOT EXISTS idx_users_user_metadata ON public.users USING gin (user_metadata);

-- Add comment
COMMENT ON COLUMN public.users.user_metadata IS 'Additional user metadata stored as JSONB (e.g., firstName, lastName, phone, preferences)';
