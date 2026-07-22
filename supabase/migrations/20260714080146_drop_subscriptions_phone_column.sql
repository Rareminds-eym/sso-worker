-- Migration: Drop phone column from subscriptions
-- Phase: Contract (removal of a field superseded by an architecture change)
-- Breaking: Yes — irreversible data loss for any non-NULL values currently stored
-- Rollback: ALTER TABLE public.subscriptions ADD COLUMN phone text; (structure only, data is not recoverable)
--
-- Context: subscriptions.phone was a denormalized copy of the user's phone number,
-- populated inconsistently at subscription-creation/upgrade time. Architecture
-- decision: users.phone (SkillPassport's own database) is now the single source
-- of truth for phone numbers. Consumers (e.g. the Sales Dashboard) must look up
-- phone via the user record instead of reading it from subscriptions.
--
-- Verified before this migration:
-- - No index, check constraint, foreign key, trigger, view, or function in the
--   public schema references subscriptions.phone.
-- - phone existed on this table since its original creation
--   (20260526000000_schema.sql) and was never referenced by any later migration.

ALTER TABLE "public"."subscriptions" DROP COLUMN IF EXISTS "phone";
