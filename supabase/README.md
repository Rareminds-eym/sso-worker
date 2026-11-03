# Environment seed configuration

Following LTE, environment seeds belong in `seed/dev` and `seed/production`. Existing SQL files remain in their original locations and have not been assigned to an environment yet. The new environment folders are empty.

From `sso-worker`:

```sh
npm run db:reset:dev
npm run db:reset:prod
```

Both commands reset the local database. The prod command selects production seed files for the local database. Neither command targets a remote database. Automatic seeding is disabled; plain `supabase db reset` applies migrations only.

Populate the environment folders before using these commands to load seed data. Legacy seed paths and archived SQL are excluded.
