-- Soft-delete marker for organizations. Used by the admin "Remove organization"
-- action (soft delete option) — organizations with deleted_at set are treated
-- as removed by application code, but the row and its history are preserved.
-- Hard delete (the other option in that same action) does not use this column;
-- it removes the row outright via performHardDeleteOrganization.
-- Date: 2026-09-25

ALTER TABLE public.organizations
  ADD COLUMN IF NOT EXISTS deleted_at timestamptz;

COMMENT ON COLUMN public.organizations.deleted_at IS
  'Set by admin soft-delete. NULL means active. Application code must filter deleted_at IS NULL for normal listings.';

CREATE INDEX IF NOT EXISTS idx_organizations_deleted_at
  ON public.organizations (deleted_at)
  WHERE deleted_at IS NOT NULL;
