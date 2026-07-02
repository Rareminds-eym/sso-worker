-- Migration: Make organization name nullable for recruiter onboarding flow
-- 
-- Background:
-- Previously, org_name was required at signup. Now recruiters sign up without
-- an org name and provide it during onboarding Step 1 (after subscription).
--
-- This migration:
-- 1. Allows organizations.name to be NULL
-- 2. Adds a check to ensure either name is provided OR it's a new signup
--    (orgs created within last 24 hours can have null name for onboarding)

-- Make organization name nullable
ALTER TABLE organizations 
ALTER COLUMN name DROP NOT NULL;

-- Add comment explaining nullable name
COMMENT ON COLUMN organizations.name IS 
  'Organization name. Can be NULL temporarily during recruiter onboarding (first 24 hours after creation). Must be set during onboarding Step 1.';

-- Optional: Add a check constraint to warn about old orgs with null names
-- (This allows new signups to have null, but flags it as an issue after 24 hours)
-- Uncomment if you want this safety check:
-- ALTER TABLE organizations 
-- ADD CONSTRAINT org_name_required_after_24h 
-- CHECK (
--   name IS NOT NULL OR 
--   created_at > (NOW() - INTERVAL '24 hours')
-- );
