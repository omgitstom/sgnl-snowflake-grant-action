# snowflake-grant-sync

Syncs SGNL access decisions to Snowflake by writing or deleting rows in the `sgnl_access_grants` table via the [Snowflake SQL API](https://docs.snowflake.com/en/developer-guide/sql-api/intro). A Snowflake [Row Access Policy](https://docs.snowflake.com/en/user-guide/security-row-intro) then reads that table at query time, making access decisions without any external call.

## How it works

When SGNL detects an identity graph change — a user gaining or losing a resource entitlement — the CAEP Hub fires this action. The action executes a single SQL statement against the `sgnl_access_grants` table:

| SGNL event | `action` input | SQL |
|---|---|---|
| Entitlement added | `grant` | `MERGE INTO sgnl_access_grants` (upsert) |
| Entitlement removed | `revoke` | `DELETE` scoped to user + resource |
| Principal deleted | `full_revoke` | `DELETE` all rows for user |

The Row Access Policy reads the grants table at query time — no external call at read time.

## Inputs

| Name | Required | Description |
|---|---|---|
| `snowflake_user` | Yes | Snowflake login name (e.g. `alice`). Automatically uppercased to match `current_user()`. |
| `action` | Yes | `grant`, `revoke`, or `full_revoke` |
| `resource_type` | For grant/revoke | Must match the value in the `department` column of the protected table (e.g. `Engineering`, `Finance`) |
| `address` | No | Snowflake SQL API base URL. Defaults to the account URL in the action config. |

## Authentication

Requires OAuth 2.0 credentials for the Snowflake `sgnl_service_role`. Configure one of:

- **Bearer token** — set `OAUTH_TOKEN` environment variable
- **OAuth2 client credentials** — configure token URL, client ID, and client secret; the framework injects the token as `OAUTH_TOKEN`

To create the OAuth Security Integration in Snowflake:

```sql
-- ACCOUNTADMIN
CREATE SECURITY INTEGRATION sgnl_oauth
    TYPE = OAUTH
    ENABLED = TRUE
    OAUTH_CLIENT = CUSTOM
    OAUTH_CLIENT_TYPE = 'CONFIDENTIAL'
    OAUTH_REDIRECT_URI = 'https://localhost'
    OAUTH_ISSUE_REFRESH_TOKENS = FALSE;

SELECT SYSTEM$SHOW_OAUTH_CLIENT_SECRETS('SGNL_OAUTH');
```

Token endpoint: `https://<account>.snowflakecomputing.com/oauth/token`

## Outputs

| Name | Description |
|---|---|
| `status` | `ok` on success |
| `action` | The action that ran |
| `snowflake_user` | Uppercased username |
| `resource_type` | Resource type that was granted or revoked |
| `completed_at` | ISO 8601 timestamp |

## Quick start

```bash
git clone https://github.com/SGNL-actions/snowflake-grant-sync
cd snowflake-grant-sync
npm install
npm test
npm run build
```

## Related

- [snowflake-revoke-session](https://github.com/SGNL-actions/snowflake-revoke-session) — terminates active Snowflake sessions via `ALTER USER`
- [Snowflake Row Access Policies](https://docs.snowflake.com/en/user-guide/security-row-intro)
- [Snowflake SQL API reference](https://docs.snowflake.com/en/developer-guide/sql-api/intro)
