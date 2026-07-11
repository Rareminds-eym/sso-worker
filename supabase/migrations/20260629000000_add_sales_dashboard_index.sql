-- Migration: Add composite index for sales dashboard queries
-- Phase: 1 of 1 (Expand)
-- Breaking: No
-- Rollback: DROP INDEX IF EXISTS idx_subscriptions_sales_dashboard;
--
-- Context: Sales dashboard queries filter by plan_type + status and ORDER BY created_at DESC.
-- The existing idx_subscriptions_status index filters only on status, leaving plan_type
-- as a sequential filter pass and requiring an explicit sort. This composite index enables
-- index-only scans for the most common sales dashboard query patterns.
--
-- Query pattern optimized:
--   SELECT user_id, id, plan_type, status
--   FROM subscriptions
--   WHERE plan_type = 'X' AND status = 'Y'
--   ORDER BY created_at DESC
--
-- CAN BE APPLIED SAFELY TO PRODUCTION:
-- - CREATE INDEX CONCURRENTLY (Supabase uses this by default)
-- - No table lock during creation
-- - Existing queries unaffected during index creation
-- - Only improves query performance, never regresses correctness

CREATE INDEX IF NOT EXISTS idx_subscriptions_sales_dashboard
  ON public.subscriptions (plan_type, status, created_at DESC);
