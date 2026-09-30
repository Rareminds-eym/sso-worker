-- Feature catalog initialization moved to ../seed/zz_seed_feature_keys.sql.
-- Retain this applied version to keep local and remote migration history aligned.
-- Existing databases retain their rows; fresh databases populate them via seeds.
-- Migrations-only deployments must apply the feature catalog seed separately.
SELECT 1;
