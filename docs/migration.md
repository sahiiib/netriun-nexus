# Migrating from Bamshi CCMP to Netriun Nexus

The importer is written in Go and invokes the `sqlite3` CLI in read-only mode. PHP and Python are not required. It preserves legacy IDs, bcrypt password hashes, groups, memberships, accounts, cached instances and audit records inside the bootstrap workspace. `group_admin` becomes `manager`, and the first legacy administrator becomes workspace owner. AWS secrets are encrypted with the target `ENCRYPTION_KEY`.

1. Create a consistent backup using SQLite's `.backup` command; do not copy a live database file without its WAL.
2. Initialize a fresh target Netriun Nexus database by starting the new application once, then stop the application and its collector. The importer refuses a populated target (other than one bootstrap user).
3. Export `DATABASE_URL` for the target and its `ENCRYPTION_KEY`. Use an isolated target PostgreSQL instance. The local Compose database is reachable on loopback port `15432` by default.
4. Validate without committing:

```sh
go run ./cmd/migrate-legacy -source /absolute/path/to/backup.db
```

5. Review the reported row counts, then commit:

```sh
go run ./cmd/migrate-legacy -source /absolute/path/to/backup.db -apply
```

6. Clear the **dedicated Netriun Nexus Redis database** before restarting. Legacy user IDs replace bootstrap IDs; old sessions must not survive this change. Never flush a Redis database shared with another application.
7. Start the app, sign in with a legacy administrator, review groups and accounts, and request collection.

The source is never modified. Import uses a single PostgreSQL transaction with exclusive table locks. Invalid references and unsupported password hashes abort the import. Dry runs roll back records and sequence changes. Legacy creation timestamps on users/groups/accounts are reset to import time; audit timestamps are preserved and interpreted as UTC where no offset exists. Legacy logrotate settings are not imported. Back up the target and encryption key before future changes.
