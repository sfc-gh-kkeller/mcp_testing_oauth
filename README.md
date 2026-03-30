# External OAuth Tokens with Snowflake Managed MCP Servers

## TL;DR

**External OAuth tokens work with Snowflake managed MCP servers.** Authentication passes through, RBAC is enforced via the role encoded in the token's `scp` claim, and both `tools/list` and `tools/call` succeed.

## What Was Tested

| Test | Method | Result |
|------|--------|--------|
| Tool discovery | `tools/list` via JSON-RPC POST | 200 OK - returned tool schema |
| Tool invocation | `tools/call` (SYSTEM_EXECUTE_SQL) | 200 OK - executed SQL, returned results |
| Auth rejection | Token role without USAGE grant | JSON-RPC error: "does not exist or not authorized" |
| Auth acceptance | Token role with proper RBAC grants | Full success |

## Architecture

```
                    ┌────────────────────────────┐
                    │   External OAuth Token      │
                    │   (JWT signed with RSA key) │
                    │                            │
                    │   iss: <your_issuer>       │
                    │   aud: <your_audience>     │
                    │   scp: session:role:<ROLE> │
                    │   name: <SF_LOGIN_NAME>    │
                    └────────────┬───────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────┐
│  Snowflake External OAuth Security Integration          │
│  (YOUR_INTEGRATION)                                     │
│                                                         │
│  - Validates JWT signature against RSA public key       │
│  - Maps token claims to Snowflake user + role           │
│  - EXTERNAL_OAUTH_ANY_ROLE_MODE = ENABLE                │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Managed MCP Server                                     │
│  (DB.SCHEMA.YOUR_MCP_SERVER)                            │
│                                                         │
│  Endpoint: POST /api/v2/databases/{db}/schemas/{schema} │
│            /mcp-servers/{name}                          │
│                                                         │
│  Tool: sql-exec-tool (SYSTEM_EXECUTE_SQL)               │
│  RBAC: Role from token must have USAGE on MCP server    │
└─────────────────────────────────────────────────────────┘
```

## How to Reproduce (Quick and Dirty)

### Prerequisites

- A Snowflake account with External OAuth configured
- `pixi` installed ([pixi.sh](https://pixi.sh))
- A Snowflake connection configured in `~/.snowflake/connections.toml`

### Step 1: Create the External OAuth Security Integration

This integration tells Snowflake how to validate your custom JWT tokens. You need an RSA key pair — the private key signs tokens, the public key goes into the integration.

```sql
CREATE OR REPLACE SECURITY INTEGRATION my_ext_oauth
    TYPE = EXTERNAL_OAUTH
    ENABLED = TRUE
    EXTERNAL_OAUTH_TYPE = CUSTOM
    EXTERNAL_OAUTH_ISSUER = '<your_issuer_url>'
    EXTERNAL_OAUTH_RSA_PUBLIC_KEY = '<your_rsa_public_key>'
    EXTERNAL_OAUTH_TOKEN_USER_MAPPING_CLAIM = 'name'
    EXTERNAL_OAUTH_SNOWFLAKE_USER_MAPPING_ATTRIBUTE = 'login_name'
    EXTERNAL_OAUTH_SCOPE_MAPPING_ATTRIBUTE = 'scp'
    EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE'
    EXTERNAL_OAUTH_AUDIENCE_LIST = ('<your_audience_url>');
```

### Step 2: Create a UDF to Generate Tokens

This UDF mints JWTs signed with the matching RSA private key. The token encodes the Snowflake username and desired role.

```sql
CREATE OR REPLACE FUNCTION generate_token_test()
RETURNS VARCHAR
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('pyjwt','cryptography')
HANDLER = 'udf'
AS $$
import jwt
from datetime import datetime, timedelta

def udf():
    # Load your RSA private key (matching the public key in the integration)
    private_key = b"""-----BEGIN RSA PRIVATE KEY-----
    <your_rsa_private_key>
    -----END RSA PRIVATE KEY-----"""

    now = datetime.utcnow()
    now_plus_100 = now + timedelta(minutes=100)

    encoded = jwt.encode({
        "iss": "<your_issuer_url>",
        "aud": "<your_audience_url>",
        "scp": "session:role:<YOUR_ROLE>",
        "name": "<YOUR_SNOWFLAKE_LOGIN_NAME>",
        "iat": now,
        "exp": now_plus_100
    }, private_key, algorithm="RS256")

    return encoded
$$;
```

> **To adapt for your own account:** Generate your own RSA key pair. Set the `name` claim to your Snowflake login name, `scp` to `session:role:<YOUR_ROLE>`, and use your own issuer/audience URLs matching the security integration.

### Step 3: Create the Managed MCP Server

```sql
CREATE OR REPLACE MCP SERVER <db>.<schema>.my_mcp_server
  FROM SPECIFICATION $$
    tools:
      - title: "SQL Execution Tool"
        name: "sql-exec-tool"
        type: "SYSTEM_EXECUTE_SQL"
        description: "A tool to execute SQL queries against the connected Snowflake database."
  $$;
```

### Step 4: Grant RBAC Permissions

The role in the token's `scp` claim needs access to the MCP server and its parent database/schema:

```sql
GRANT USAGE ON DATABASE <db> TO ROLE <your_role>;
GRANT USAGE ON SCHEMA <db>.<schema> TO ROLE <your_role>;
GRANT USAGE ON MCP SERVER <db>.<schema>.my_mcp_server TO ROLE <your_role>;
```

### Step 5: Run the Test

```bash
cd /path/to/mcp_testing_oauth
pixi install
pixi run test
```

Or with a specific connection:

```bash
SNOWFLAKE_CONNECTION_NAME=my_connection pixi run test
```

### Expected Output

```
============================================================
TEST 1: tools/list — discover tools via external OAuth
============================================================
{
  "http_status": 200,
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {
        "name": "sql-exec-tool",
        "description": "A tool to execute SQL queries ...",
        "inputSchema": { ... }
      }
    ]
  }
}

============================================================
TEST 2: tools/call — execute SQL via external OAuth
============================================================
{
  "http_status": 200,
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"result_set\":{\"data\":[[\"<SCHEMA>\",\"<ROLE>\",\"MCP external OAuth test OK\"]]}}"
      }
    ],
    "isError": false
  }
}

============================================================
RESULT: External OAuth tokens WORK with managed MCP servers
============================================================
```

## Gotchas and Lessons Learned

| Gotcha | Detail |
|--------|--------|
| **`Accept` header required** | Must send `Accept: application/json` or you get error code `391902`: "Unsupported Accept header null" |
| **RBAC is fully enforced** | The role from the token's `scp` claim must have `USAGE` on the MCP server AND `USAGE` on the parent database + schema. Without this you get: "MCP server does not exist or not authorized" (not a 401/403 — it's an HTTP 200 with a JSON-RPC error) |
| **SQL tool param name** | The `SYSTEM_EXECUTE_SQL` tool expects `sql` as the input parameter, not `statement` |
| **ANY_ROLE_MODE** | The external OAuth integration needs `EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE'` for the token to assume the role in the `scp` claim |
| **Hostname format** | Use hyphens not underscores in account URLs (per Snowflake docs: "MCP servers have connection issues with hostnames containing underscores") |
| **Auth errors are subtle** | Failed auth doesn't return HTTP 401/403. It returns HTTP 200 with a JSON-RPC `-32603` error. Inspect the response body carefully |

## curl Quick Test

If you just want to test with curl after generating a token:

```bash
TOKEN=$(snowsql -c my_conn -q "SELECT generate_token_test()" -o output_format=plain -o header=false)

curl -s -X POST \
  "https://<account>.snowflakecomputing.com/api/v2/databases/<DB>/schemas/<SCHEMA>/mcp-servers/<MCP_SERVER_NAME>" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list"
  }'
```

## Files in This Project

| File | Description |
|------|-------------|
| `test_mcp_external_oauth.py` | Python test script — generates token via UDF, hits MCP endpoint, reports results |
| `pyproject.toml` | Pixi project config with `snowflake-connector-python` dependency |
| `README.md` | This file |
