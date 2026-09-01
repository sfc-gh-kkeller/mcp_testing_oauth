# MCP Server Role Control with External OAuth and PATs

## Summary of Findings

This repository documents tested approaches for controlling which Snowflake role is used when connecting to a managed MCP server via External OAuth or Programmatic Access Tokens (PATs). All findings are validated against a real Snowflake account with reproducible test scripts.

**Key discovery:** The `X-Snowflake-Role` HTTP header + scoped External OAuth tokens provides full per-request role control and domain isolation on the MCP path — without touching `DEFAULT_ROLE`.

## Role Control Methods (Tested & Validated)

| # | Method | Role override? | Secondary roles | Domain isolation? | Per-request? |
|---|--------|---------------|-----------------|-------------------|--------------|
| 1 | `session:role-any` (no header) | No (uses DEFAULT_ROLE) | ALL active | No | No |
| 2 | `session:role-any` + `X-Snowflake-Role: X` | Yes | ALL active | No | Yes |
| 3 | `session:role:X` + `X-Snowflake-Role: X` | Yes | **NONE** | **Yes** | Yes |
| 4 | PAT with `ROLE_RESTRICTION=X` | Yes | **NONE** | **Yes** | Per-token |
| 5 | `session:role-any` + Session Policy `ALLOWED_SECONDARY_ROLES=(A,B)` | No (DEFAULT_ROLE) | **Only A,B** | **Yes (curated)** | No |
| 6 | Token scp array `[role:A, role:B]` + `X-Snowflake-Role` per request | Yes (switches between A,B) | NONE per request | Yes (per-request) | Yes |

## Detailed Findings

### 1. `X-Snowflake-Role` Header Works on MCP Endpoints

The [REST API context headers](https://docs.snowflake.com/en/developer-guide/snowflake-rest-api/setting-context) (`X-Snowflake-Role`, `X-Snowflake-Warehouse`) work on the MCP server endpoint. When provided, `X-Snowflake-Role` **takes precedence over DEFAULT_ROLE**.

This means:
- No need to `ALTER USER SET DEFAULT_ROLE` per session
- The role is controlled per HTTP request
- Combined with a scoped token, provides full isolation

### 2. Token Scope Controls Secondary Roles

| Token scope | Secondary roles behavior |
|-------------|------------------------|
| `session:role-any` | Secondary roles **active** (all granted roles) |
| `session:role:X` | Secondary roles **disabled** (only X's grants) |

This is the key to isolation: a token scoped to `session:role:DEMO_DOMAIN_FINANCE` with `X-Snowflake-Role: DEMO_DOMAIN_FINANCE` gives a session with ONLY finance privileges — secondary roles are not active, so no other role's grants apply.

### 3. PAT with ROLE_RESTRICTION

Programmatic Access Tokens with `ROLE_RESTRICTION` override DEFAULT_ROLE completely and disable secondary roles. This works identically to approach #3 above but without needing an External OAuth integration.

```sql
ALTER USER <service_user> ADD PROGRAMMATIC ACCESS TOKEN <name>
  ROLE_RESTRICTION = 'DEMO_DOMAIN_FINANCE'
  DAYS_TO_EXPIRY = 30;
```

Use with header: `X-Snowflake-Authorization-Token-Type: PROGRAMMATIC_ACCESS_TOKEN`

### 4. Session Policy for Curated Multi-Domain Access

For users who need combined access from exactly N domains (but not all):

```sql
CREATE SESSION POLICY my_policy
  ALLOWED_SECONDARY_ROLES = ('DOMAIN_FINANCE', 'DOMAIN_MARKETING');
ALTER USER <user> SET SESSION POLICY my_policy;
```

With `session:role-any`, the session gets ONLY finance + marketing as secondary roles. Engineering (and all other roles) are blocked even though the token theoretically permits them.

### 5. Token Scope Array = Per-Request Role Switching Allowlist

The `scp` claim can be a JSON array of roles:
```json
{"scp": ["session:role:DOMAIN_FINANCE", "session:role:DOMAIN_MARKETING"]}
```

This allows the bearer to switch between FINANCE and MARKETING via `X-Snowflake-Role` per request, but blocks any other role (e.g., ENGINEERING). Each request still has no secondary roles — it's one role at a time.

### 6. OAUTH_AUTHORIZATION_SERVER and OAUTH_SCOPES_SUPPORTED (Jul 2026)

These schema-level parameters:
- **`OAUTH_AUTHORIZATION_SERVER`** — Binds MCP servers to an external IdP. Only tokens from that issuer are accepted.
- **`OAUTH_SCOPES_SUPPORTED`** — Controls what's advertised in Protected Resource Metadata (RFC 9728).

**Important:** `OAUTH_SCOPES_SUPPORTED` only controls metadata advertisement. It does NOT enable roles beyond DEFAULT_ROLE for External OAuth. You need `X-Snowflake-Role` header for that.

### 7. Ownership and Secondary Roles Interaction

When `session:role-any` is used with `DEFAULT_SECONDARY_ROLES = ('ALL')`, ALL of the user's granted roles become active as secondary roles — including roles that OWN objects. This means a user connecting with role A as primary can access an MCP server owned by role X (with no explicit USAGE grant to A), because role X is active as a secondary role.

This is expected behavior (secondary roles provide combined privileges from all active roles), but worth understanding for access control design.

**To restrict this, use any of these approaches:**

| Method | Effect |
|--------|--------|
| Token scope `session:role:X` | Disables all secondary roles for that session |
| `DEFAULT_SECONDARY_ROLES = ()` on user | Permanently disables secondary roles |
| Session Policy `ALLOWED_SECONDARY_ROLES = (...)` | Only listed roles activate as secondaries |
| Session Policy `BLOCKED_SECONDARY_ROLES = ('OWNER_ROLE')` | Specifically blocks that role from being a secondary |

All four are tested and confirmed to prevent access via secondary role inheritance.

### 8. Role Hierarchy and MCP Access

Role hierarchy (inheritance) applies to MCP access as it does to any other Snowflake object. If ROLE_A inherits from ROLE_B (`GRANT ROLE ROLE_B TO ROLE ROLE_A`), then ROLE_A has all of ROLE_B's privileges — including OWNERSHIP or USAGE on MCP servers.

This means a token scoped to `session:role:ROLE_A` with `X-Snowflake-Role: ROLE_A` gives access to MCP servers owned by ROLE_B, even with secondary roles disabled. This is standard RBAC behavior — ROLE_A's effective privileges include everything inherited from ROLE_B.

To verify what a role inherits:
```sql
SHOW GRANTS TO ROLE <role_name>;  -- look for USAGE on other roles
```

## What Does NOT Work

| Approach | Why it fails |
|----------|-------------|
| `USE ROLE` inside MCP session | Blocked (error 399517) — hard-blocked at engine level |
| SQL chaining with `USE ROLE` | Single-statement enforcement + 399517 |
| Token `session:role:X` without `X-Snowflake-Role` header | Fails with 390317 if DEFAULT_ROLE != X |
| `OAUTH_SCOPES_SUPPORTED` overriding DEFAULT_ROLE | It's metadata-only, not enforcement |
| `DEFAULT_SECONDARY_ROLES = ('ROLE_A', 'ROLE_B')` | Invalid syntax — only accepts `('ALL')` or `()` |

## Architecture Examples

```
External OAuth Integration:
  EXTERNAL_OAUTH_ANY_ROLE_MODE = ENABLE

Schema parameters:
  OAUTH_AUTHORIZATION_SERVER = <integration>
  OAUTH_SCOPES_SUPPORTED = 'session:role:DOMAIN_A,session:role:DOMAIN_B,session:role-any'

Per MCP client (e.g., Claude Code):
  Token: session:role:DOMAIN_A
  Header: X-Snowflake-Role: DOMAIN_A
  Result: Isolated to DOMAIN_A only (no secondary roles)

For broad access (e.g., internal analytics):
  Token: session:role-any
  Header: X-Snowflake-Role: MCP_ACCESS
  Result: All secondary roles active, full cross-domain access

For curated multi-domain:
  Session Policy: ALLOWED_SECONDARY_ROLES = ('DOMAIN_A', 'DOMAIN_B')
  Token: session:role-any
  Result: Only A + B as secondaries, all others blocked
```

## Claude Code CLI Configuration Example

```bash
# Single domain isolation (finance only)
claude mcp add snowflake-finance <MCP_URL> \
  --transport http \
  --header "Authorization: Bearer <token_scoped_to_finance>" \
  --header "X-Snowflake-Role: DEMO_DOMAIN_FINANCE" \
  --header "Accept: application/json" \
  -s project
```

With a token whose `scp` = `session:role:DEMO_DOMAIN_FINANCE`, this gives Claude Code access to ONLY finance data.

## Setup & Usage

### With pip (standard Python 3.11+)

```bash
pip install pyjwt cryptography snowflake-connector-python
SNOWFLAKE_CONNECTION_NAME=<conn> SNOWFLAKE_ACCOUNT_URL=https://<orgname>-<account>.snowflakecomputing.com python test_02_external_oauth_role_control.py
```

### With pixi (managed environment)

```bash
pixi install
SNOWFLAKE_CONNECTION_NAME=<conn> SNOWFLAKE_ACCOUNT_URL=https://<orgname>-<account>.snowflakecomputing.com pixi run python test_02_external_oauth_role_control.py
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SNOWFLAKE_CONNECTION_NAME` | Yes | Connection name from `~/.snowflake/connections.toml` |
| `SNOWFLAKE_ACCOUNT_URL` | Yes | Full account URL (e.g. `https://myorg-myacct.snowflakecomputing.com`) |
| `SNOWFLAKE_WAREHOUSE` | No | Warehouse to use (default: `S2`) |

### Scripts

| File | Purpose | Run with |
|------|---------|----------|
| `test_01_external_oauth_basic.py` | Does external OAuth work with MCP at all? | `python test_01_external_oauth_basic.py` |
| `test_02_external_oauth_role_control.py` | External OAuth role patterns: broad, header isolation, session policy, scp array | `python test_02_external_oauth_role_control.py` |
| `test_03_pat_role_isolation.py` | PAT with ROLE_RESTRICTION (per-token domain isolation) | `python test_03_pat_role_isolation.py` |
| `test_04_interactive_demo.py` | Interactive demo + `--agent-test` to mint tokens for MCP clients | `python test_04_interactive_demo.py --agent-test` |
| `test_05_session_policy_secondary_roles.py` | Session Policy ALLOWED/BLOCKED_SECONDARY_ROLES behavior | `python test_05_session_policy_secondary_roles.py` |
| `test_06_ownership_and_secondary_roles.py` | How MCP ownership interacts with secondary roles | `python test_06_ownership_and_secondary_roles.py` |

Each script creates all required infrastructure (keys, integration, roles, tables, MCP server) from scratch. Requires ACCOUNTADMIN.

## Gotchas

| Issue | Detail |
|-------|--------|
| `X-Snowflake-Role` required for non-default role | Without the header, MCP always uses DEFAULT_ROLE |
| Token scope gates the header | `X-Snowflake-Role: X` only works if X is in the token's `scp` (or scp is `session:role-any`) |
| MCP single-statement only | Cannot chain SQL statements (error: "statement count N did not match desired 1") |
| Network policy for External OAuth | Your calling IP must be in the account's network policy |
| `Accept: application/json` required | Without it: error 391902 "Unsupported Accept header null" |
| `EXTERNAL_OAUTH_ANY_ROLE_MODE = ENABLE` | Required for `session:role-any` to work |
| Auth errors are HTTP 200 + JSON-RPC error | Not HTTP 401/403 — inspect the response body |

## FYI: Related Auth Behavior in Cortex Agents and OAuth

The following features are not specific to MCP servers, but affect how authentication and authorization work for AI agents in Snowflake.

### Agent Identity (`IS_AGENTIC` on OAuth Integrations)

Snowflake OAuth custom integrations support an `IS_AGENTIC` parameter that marks all sessions through that integration as agent sessions:

```sql
CREATE SECURITY INTEGRATION my_agent_oauth
  TYPE = OAUTH
  OAUTH_CLIENT = CUSTOM
  OAUTH_CLIENT_TYPE = 'CONFIDENTIAL'
  OAUTH_REDIRECT_URI = 'https://my-agent.example.com/callback'
  IS_AGENTIC = TRUE;
```

When `IS_AGENTIC = TRUE`:
- `SYS_CONTEXT('SNOWFLAKE$CURRENT', 'IS_AGENT_ACTIVATED')` returns `TRUE` for those sessions
- `QUERY_HISTORY.agent_type` = `EXTERNAL_AGENT` for all queries
- `ACCESS_HISTORY.agents_info` is populated with agent details
- Data protection policies (masking, row access, projection, etc.) can branch on `IS_AGENT_ACTIVATED` to restrict what agents see:

```sql
CREATE MASKING POLICY ssn_agent_mask AS (val STRING) RETURNS STRING ->
  CASE
    WHEN SYS_CONTEXT('SNOWFLAKE$CURRENT', 'IS_AGENT_ACTIVATED')::BOOLEAN
      THEN '***-**-' || RIGHT(val, 4)
    ELSE val
  END;
```

This is a governance flag, not an auth-flow modifier — the underlying OAuth protocol is identical.

### `SERVICE_AGENT` User Type

For autonomous agents that act under their own identity (rather than on behalf of a human user):

```sql
CREATE USER my_agent_user
  TYPE = SERVICE_AGENT
  DEFAULT_ROLE = agent_role
  DEFAULT_WAREHOUSE = agent_wh;
```

- Every session is automatically agent-active (`IS_AGENT_ACTIVATED = TRUE`)
- Non-interactive only: supports workload identity federation, key-pair auth, and PATs
- Unlike `SERVICE` users, does not require a network policy before PAT creation

### Cortex Agent Authorization Model

Cortex Agents use the **querying user's default role**, not the role active in their session. This is distinct from MCP server behavior (which respects `X-Snowflake-Role` and token scope).

| Aspect | MCP Server | Cortex Agent |
|--------|-----------|-------------|
| Role resolution | `X-Snowflake-Role` header > token scope > DEFAULT_ROLE | Always DEFAULT_ROLE |
| Secondary roles | Controlled by token scope and session policy | Controlled by DEFAULT_SECONDARY_ROLES |
| Per-request role switching | Yes (via header) | No |
| Session role matters | Yes | No (ignored in favor of default role) |

For Cortex Agents, the default role must have USAGE on the agent, its database/schema, warehouse, and all tool targets (search services, semantic views, functions).
