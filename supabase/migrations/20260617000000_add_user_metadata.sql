-- Phase: 1 of 1 (Expand)
-- Breaking: No — nullable with default
-- Backward compatible: Yes

ALTER TABLE users ADD COLUMN IF NOT EXISTS user_metadata JSONB DEFAULT '{}';
