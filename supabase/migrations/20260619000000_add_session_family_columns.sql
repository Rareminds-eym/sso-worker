-- Add session family tracking columns
-- family_id: Links related sessions (e.g., after org switch, same family)
-- family_created_at: Timestamp when the session family was created

ALTER TABLE public.sessions 
ADD COLUMN IF NOT EXISTS family_id uuid,
ADD COLUMN IF NOT EXISTS family_created_at timestamp with time zone;

-- Add index for better query performance
CREATE INDEX IF NOT EXISTS idx_sessions_family_id ON public.sessions(family_id);

-- Add comments
COMMENT ON COLUMN public.sessions.family_id IS 'Links related sessions together (e.g., sessions after org switch belong to same family)';
COMMENT ON COLUMN public.sessions.family_created_at IS 'Timestamp when the session family was originally created';
