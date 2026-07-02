-- Migration: Add pg_cron extension and schedule token cleanup
-- Phase: 1 of 1 (Expand)
-- Breaking: No
-- Rollback: SELECT cron.unschedule('cleanup-expired-tokens'); DROP EXTENSION IF EXISTS pg_cron CASCADE;
--
-- Context: The cleanup_expired_tokens() function already exists but has no scheduled trigger.
-- This migration adds pg_cron extension and schedules the function to run daily at 3AM UTC.
--
-- CAN BE APPLIED SAFELY TO PRODUCTION:
-- - pg_cron is a standard Supabase extension
-- - Scheduling is non-blocking
-- - Function already exists and is tested
-- - Only adds automation, doesn't change data

-- Add pg_cron extension if not present
CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Schedule cleanup_expired_tokens to run daily at 3AM UTC
SELECT cron.schedule(
  'cleanup-expired-tokens',
  '0 3 * * *',  -- Daily at 3AM UTC
  'SELECT public.cleanup_expired_tokens();'
);

-- Grant usage of pg_cron to service role (required for scheduling)
GRANT USAGE ON SCHEMA cron TO service_role;
