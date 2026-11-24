# Environment seed configuration

Environment seeds belong in `seed/dev` and `seed/production`. Each reset loads SQL files directly inside its selected folder in filename order. Archived and nested files are excluded.

From `sso-worker`:

```sh
npm run db:reset:dev
npm run db:reset:prod
```

Both commands reset the local database. The prod command selects production seed files for the local database. Neither command targets a remote database. Automatic seeding is disabled; plain `supabase db reset` applies migrations only.

## Subscription catalog reset baseline

Both environment folders include [20270326000000_seed_subscription_catalog.sql](seed/dev/20270326000000_seed_subscription_catalog.sql), after the initial data and older recruiter seeds. It restores all 21 BRD plans plus the retained Hybrid offer, including canonical plan configuration, 44 immutable draft/credit bundles, new current publication receipts and pointers created through the normal publication RPC with every policy trigger enabled and the original subscriber-free Hybrid adoption evidence required by the capacity guard. Explicitly replaced legacy offers become inactive; their identities, subscribers and purchased terms remain intact. The original product and publication actors must already exist in the environment's initial seed; missing prerequisites abort the transaction.

The source is [the catalog reset snapshot](../config/subscriptions/reset-catalog.json), captured through read-only local owner queries. It contains catalog definitions and publication evidence, with no subscribers, payments, credentials or user profiles. It incorporates existing owner-approved policy, including paid assessment retakes and negotiated sales-only Enterprise/Hybrid terms. Resetting the catalog does not activate subscribers or allocate credits. Historical publication events in the snapshot remain archival evidence: the reset does not replay them or rewrite their original terms. Current publications start with no previous revision and receive new IDs and timestamps. All 44 immutable draft/credit bundles and application projections remain available as revision dependencies; historical subscribers are not imported. Restoring historical subscriber/audit state would require a separately reviewed, versioned import contract.

The [offline generator](../scripts/generate-subscription-seeds.mjs) writes matching SQL to both SSO and SkillPassport environment folders. From `sso-worker`, with the sibling SkillPassport checkout available:

```sh
npm run db:seed:generate
npm run db:seed:check
npm run test:subscription-seeds
```

The tests execute SQL with existing table/RPC migrations in an in-process PostgreSQL engine and synthetic bootstrap data. They check replay, conflicting immutable evidence, feature UUID preservation, matching application projections, current flat grants, the real Hybrid and free-publication lifecycle guards, invalid-policy rejection, and reset seed discovery. A Vitest regression also calls the actual quota reader against seed-created PostgreSQL state with a missing-grant control. They do not reset a running database or exercise the complete migration chain.

The commerce activation migration now uses [20270324000000_subscription_commerce_activation.sql](migrations/20270324000000_subscription_commerce_activation.sql), with unchanged SQL, to remove its version collision with verified free entry. Fresh resets apply each migration once and preserve the original commerce-before-free-entry ordering. For an existing database where commerce activation already ran under the former duplicate version, inspect the installed function definitions and migration history before any migration command. Reconcile that target’s history only after confirming the entire migration is installed and obtaining explicit approval for the specific repair. Do not blindly rerun it: its function rename is not replayable. Historical audit evidence retains the filename that existed when it was recorded.

Executing either reset or applying a seed to any target requires explicit approval for that target and action. Preparing these files does not authorize execution.
