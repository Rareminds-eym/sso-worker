-- Soundarya College: raise SSO subscription seats to cover the 5000-seat license pool.
-- This is the SOURCE value. SkillPassport's subscription_cache is only a shadow —
-- fixing just the shadow gets overwritten on the next SSO re-sync and breaks
-- future seeds with 'Total pool allocation (5000) exceeds subscription seats (1)'.
-- Run BEFORE the SkillPassport enterprise seed
-- (skillpassport/supabase/seed/seed_soundarya_fix_subscription_seats.sql).
UPDATE subscriptions SET seat_count = 5000, updated_at = NOW()
WHERE id = 'd3876903-b74e-55d7-910f-90907ea3e11f';
