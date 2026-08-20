#!/usr/bin/env python3
"""
==============================================================================
  MCP External OAuth: Multi-Role Customer Concern Validation
==============================================================================

  This script demonstrates that the 4 customer concerns about Snowflake
  managed MCP servers and external OAuth role limitations are NOW RESOLVED
  using the Jul 2026 GA features:

    - OAUTH_AUTHORIZATION_SERVER (bind MCP to external IdP)
    - OAUTH_SCOPES_SUPPORTED (advertise roles in Protected Resource Metadata)
    - session:role-any (accept any granted role)
    - DEFAULT_SECONDARY_ROLES = ALL (activate all secondary roles)

  CUSTOMER CONCERNS:
    1. Cannot give the MCP server an explicit role
    2. USE ROLE rejected; secondary roles not usable on OAuth path
    3. Ever-growing default role (only way to add access)
    4. One MCP server per role; does not scale across domains

  PREREQUISITES:
    - pixi install  (installs pyjwt, cryptography, snowflake-connector-python)
    - A Snowflake connection configured in ~/.snowflake/connections.toml
    - ACCOUNTADMIN access (to create integrations, roles, set parameters)

  USAGE:
    SNOWFLAKE_CONNECTION_NAME=<conn> SNOWFLAKE_ACCOUNT_URL=<url> pixi run demo

    --agent-test  Mint a 10-minute external OAuth token and print MCP config
                  for testing with Claude Code or other MCP clients.

  The script sets up everything from scratch (keys, integration, roles, tables,
  MCP server, parameters) and then walks through each concern step by step.
==============================================================================
"""

import argparse
import os
import sys
import json
import time
import urllib.request
import urllib.error
import base64
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import snowflake.connector


# ---------------------------------------------------------------------------
# Configuration (override via environment variables)
# ---------------------------------------------------------------------------
CONN_NAME = os.getenv("SNOWFLAKE_CONNECTION_NAME", "default")
ACCOUNT_URL = os.getenv("SNOWFLAKE_ACCOUNT_URL")
DB = os.getenv("MCP_DATABASE", "MCP_DEMO_DB")
SCHEMA = os.getenv("MCP_SCHEMA", "MULTI_ROLE_TEST")
MCP_SERVER = "DEMO_MCP_SERVER"
INTEGRATION = "MCP_EXT_OAUTH_DEMO"
ISSUER = "https://mcp-demo-issuer.example.com"

# Roles simulating different data domains
ROLE_MCP_ACCESS = "DEMO_MCP_ACCESS"       # Narrow: only MCP server usage
ROLE_FINANCE = "DEMO_DOMAIN_FINANCE"      # Domain: finance data
ROLE_MARKETING = "DEMO_DOMAIN_MARKETING"  # Domain: marketing data
ROLE_ENGINEERING = "DEMO_DOMAIN_ENGINEERING"  # Domain: engineering data


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def banner(text, char="="):
    print()
    print(char * 70)
    print(f"  {text}")
    print(char * 70)
    print()


def step(number, description):
    print(f"  Step {number}: {description}")


def result_ok(text):
    print(f"    -> {text}")


def result_fail(text):
    print(f"    !! {text}")


def mcp_request(endpoint, headers, method, params=None, req_id=1):
    payload = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params:
        payload["params"] = params
    data = json.dumps(payload).encode()
    req = urllib.request.Request(endpoint, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return {"http_error": e.code, "response": json.loads(body)}
        except json.JSONDecodeError:
            return {"http_error": e.code, "response": body}


def mcp_sql(endpoint, headers, sql, req_id=1):
    return mcp_request(endpoint, headers, "tools/call",
                       params={"name": "sql-exec-tool", "arguments": {"sql": sql}},
                       req_id=req_id)


def extract_data(response):
    """Extract result data from MCP response, or return error info."""
    try:
        content = response["result"]["content"][0]["text"]
        parsed = json.loads(content)
        if "result_set" in parsed:
            return {"ok": True, "data": parsed["result_set"]["data"],
                    "columns": [c["name"] for c in parsed["result_set"]["resultSetMetaData"]["rowType"]]}
        return {"ok": False, "error": content}
    except (KeyError, json.JSONDecodeError, IndexError):
        return {"ok": False, "error": str(response)}


def is_mcp_error(response):
    """Check if MCP returned an error."""
    try:
        return response.get("result", {}).get("isError", False)
    except AttributeError:
        return "http_error" in response


# ---------------------------------------------------------------------------
# Main Demo
# ---------------------------------------------------------------------------

def main():
    if not ACCOUNT_URL:
        print("ERROR: Set SNOWFLAKE_ACCOUNT_URL environment variable.")
        print("  Example: https://<orgname>-<account_name>.snowflakecomputing.com")
        sys.exit(1)

    banner("CONNECTING TO SNOWFLAKE")
    print(f"  Connection: {CONN_NAME}")
    print(f"  Account URL: {ACCOUNT_URL}")
    print()

    conn = snowflake.connector.connect(connection_name=CONN_NAME)
    cur = conn.cursor()

    # Identify current user
    cur.execute("SELECT CURRENT_USER()")
    username = cur.fetchone()[0]
    cur.execute(f"DESCRIBE USER {username}")
    user_props = {r[0]: r[1] for r in cur.fetchall()}
    login_name = user_props["LOGIN_NAME"]
    original_default_role = user_props["DEFAULT_ROLE"]

    print(f"  User: {username}")
    print(f"  Login name: {login_name}")
    print(f"  Current DEFAULT_ROLE: {original_default_role}")

    # =========================================================================
    # PHASE 1: SETUP
    # =========================================================================
    banner("PHASE 1: INFRASTRUCTURE SETUP", "=")
    print("  Creating all objects from scratch (integration, roles, tables, MCP server)")
    print()

    cur.execute("USE ROLE ACCOUNTADMIN")

    # Generate RSA key pair for token signing
    step(1, "Generate RSA-2048 key pair for JWT signing")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    pub_b64 = base64.b64encode(public_der).decode()
    result_ok("Key pair generated (private key stays in memory, public key goes to integration)")

    # Database and schema
    step(2, "Create database and schema")
    cur.execute(f"CREATE DATABASE IF NOT EXISTS {DB}")
    cur.execute(f"CREATE SCHEMA IF NOT EXISTS {DB}.{SCHEMA}")
    result_ok(f"Created {DB}.{SCHEMA}")

    # External OAuth integration
    step(3, "Create External OAuth security integration")
    cur.execute(f"""CREATE OR REPLACE SECURITY INTEGRATION {INTEGRATION}
        TYPE = EXTERNAL_OAUTH
        ENABLED = TRUE
        EXTERNAL_OAUTH_TYPE = CUSTOM
        EXTERNAL_OAUTH_ISSUER = '{ISSUER}'
        EXTERNAL_OAUTH_RSA_PUBLIC_KEY = '{pub_b64}'
        EXTERNAL_OAUTH_TOKEN_USER_MAPPING_CLAIM = 'name'
        EXTERNAL_OAUTH_SNOWFLAKE_USER_MAPPING_ATTRIBUTE = 'login_name'
        EXTERNAL_OAUTH_SCOPE_MAPPING_ATTRIBUTE = 'scp'
        EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE'
        EXTERNAL_OAUTH_AUDIENCE_LIST = ('{ACCOUNT_URL}')""")
    result_ok(f"Integration {INTEGRATION} with ANY_ROLE_MODE=ENABLE")

    # Set new parameters on schema
    step(4, "Bind external OAuth to schema (NEW Jul 2026 parameters)")
    cur.execute(f"""ALTER SCHEMA {DB}.{SCHEMA}
        SET OAUTH_AUTHORIZATION_SERVER = {INTEGRATION}
            OAUTH_SCOPES_SUPPORTED = 'session:role-any'""")
    result_ok("OAUTH_AUTHORIZATION_SERVER = integration")
    result_ok("OAUTH_SCOPES_SUPPORTED = 'session:role-any'")

    # Create domain roles
    step(5, "Create domain-specific roles (simulating real org structure)")
    all_roles = [ROLE_MCP_ACCESS, ROLE_FINANCE, ROLE_MARKETING, ROLE_ENGINEERING]
    for role in all_roles:
        cur.execute(f"CREATE ROLE IF NOT EXISTS {role}")
        cur.execute(f"GRANT ROLE {role} TO USER {username}")
    result_ok(f"Roles: {', '.join(all_roles)}")
    result_ok(f"All granted to user {username}")

    # MCP access role: minimal (only MCP server usage)
    step(6, "Configure MCP access role (MINIMAL — least privilege)")
    cur.execute(f"GRANT USAGE ON DATABASE {DB} TO ROLE {ROLE_MCP_ACCESS}")
    cur.execute(f"GRANT USAGE ON SCHEMA {DB}.{SCHEMA} TO ROLE {ROLE_MCP_ACCESS}")
    result_ok(f"{ROLE_MCP_ACCESS} has ONLY: USAGE on DB + SCHEMA + MCP SERVER")
    result_ok("NO select grants on any tables — this is intentionally narrow")

    # Create MCP server
    step(7, "Create MCP server with SQL execution tool")
    cur.execute(f"""CREATE OR REPLACE MCP SERVER {DB}.{SCHEMA}.{MCP_SERVER}
        FROM SPECIFICATION $$
        tools:
          - title: "SQL Execution"
            name: "sql-exec-tool"
            type: "SYSTEM_EXECUTE_SQL"
            description: "Execute SQL queries against Snowflake"
        $$""")
    cur.execute(f"GRANT USAGE ON MCP SERVER {DB}.{SCHEMA}.{MCP_SERVER} TO ROLE {ROLE_MCP_ACCESS}")
    result_ok(f"MCP server: {DB}.{SCHEMA}.{MCP_SERVER}")

    # Create domain tables with domain-specific access
    step(8, "Create domain tables with isolated access grants")

    cur.execute(f"CREATE OR REPLACE TABLE {DB}.{SCHEMA}.FINANCE_REVENUE (quarter VARCHAR, revenue NUMBER, region VARCHAR)")
    cur.execute(f"INSERT INTO {DB}.{SCHEMA}.FINANCE_REVENUE VALUES ('Q1-2026', 12500000, 'EMEA'), ('Q2-2026', 14200000, 'APAC'), ('Q3-2026', 11800000, 'AMER')")
    cur.execute(f"GRANT SELECT ON TABLE {DB}.{SCHEMA}.FINANCE_REVENUE TO ROLE {ROLE_FINANCE}")
    result_ok(f"FINANCE_REVENUE -> granted to {ROLE_FINANCE}")

    cur.execute(f"CREATE OR REPLACE TABLE {DB}.{SCHEMA}.MARKETING_CAMPAIGNS (campaign VARCHAR, spend NUMBER, leads INT)")
    cur.execute(f"INSERT INTO {DB}.{SCHEMA}.MARKETING_CAMPAIGNS VALUES ('Brand-Awareness', 500000, 12000), ('Product-Launch', 750000, 8500)")
    cur.execute(f"GRANT SELECT ON TABLE {DB}.{SCHEMA}.MARKETING_CAMPAIGNS TO ROLE {ROLE_MARKETING}")
    result_ok(f"MARKETING_CAMPAIGNS -> granted to {ROLE_MARKETING}")

    cur.execute(f"CREATE OR REPLACE TABLE {DB}.{SCHEMA}.ENGINEERING_INCIDENTS (severity VARCHAR, count INT, mttr_hours FLOAT)")
    cur.execute(f"INSERT INTO {DB}.{SCHEMA}.ENGINEERING_INCIDENTS VALUES ('P1', 3, 2.5), ('P2', 12, 8.0), ('P3', 47, 24.0)")
    cur.execute(f"GRANT SELECT ON TABLE {DB}.{SCHEMA}.ENGINEERING_INCIDENTS TO ROLE {ROLE_ENGINEERING}")
    result_ok(f"ENGINEERING_INCIDENTS -> granted to {ROLE_ENGINEERING}")

    # Configure user: narrow default role + ALL secondary roles
    step(9, "Configure user for least-privilege MCP access")
    cur.execute(f"ALTER USER {username} SET DEFAULT_ROLE = '{ROLE_MCP_ACCESS}' DEFAULT_SECONDARY_ROLES = ('ALL')")
    result_ok(f"DEFAULT_ROLE = {ROLE_MCP_ACCESS} (narrow MCP access only)")
    result_ok("DEFAULT_SECONDARY_ROLES = ('ALL') (domain roles activate as secondary)")

    # Network policy check (add IP if needed)
    step(10, "Ensure caller IP is in network policy")
    try:
        with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=5) as resp:
            my_ip = resp.read().decode().strip()
        cur.execute(f"""CREATE NETWORK RULE IF NOT EXISTS {DB}.{SCHEMA}.DEMO_INGRESS
            MODE = INGRESS TYPE = IPV4 VALUE_LIST = ('{my_ip}')""")
        cur.execute("SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT")
        policy_row = cur.fetchone()
        if policy_row and policy_row[1]:
            cur.execute(f"ALTER NETWORK POLICY {policy_row[1]} ADD ALLOWED_NETWORK_RULE_LIST = ('{DB}.{SCHEMA}.DEMO_INGRESS')")
        result_ok(f"IP {my_ip} allowed")
    except Exception as e:
        result_ok(f"Network rule setup skipped ({e})")

    print()
    print("  Waiting for parameter propagation...")
    time.sleep(3)

    # =========================================================================
    # PHASE 2: MINT TOKEN AND CONNECT
    # =========================================================================
    banner("PHASE 2: AUTHENTICATE VIA EXTERNAL OAUTH", "=")

    step(1, "Mint JWT token with scope 'session:role-any'")
    now = datetime.now(timezone.utc)
    token = jwt.encode({
        "iss": ISSUER,
        "aud": ACCOUNT_URL,
        "scp": "session:role-any",
        "name": login_name,
        "iat": now,
        "exp": now + timedelta(minutes=30),
    }, private_pem, algorithm="RS256")
    result_ok(f"Token minted ({len(token)} chars), signed with RSA-256")
    result_ok(f"Claims: iss={ISSUER}, scp=session:role-any, name={login_name}")

    endpoint = f"{ACCOUNT_URL}/api/v2/databases/{DB}/schemas/{SCHEMA}/mcp-servers/{MCP_SERVER}"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }

    step(2, "Verify MCP server is reachable")
    r = mcp_request(endpoint, headers, "tools/list")
    if "result" in r and "tools" in r["result"]:
        tools = [t["name"] for t in r["result"]["tools"]]
        result_ok(f"Connected! Tools available: {tools}")
    else:
        result_fail(f"Connection failed: {r}")
        cur.execute(f"ALTER USER {username} SET DEFAULT_ROLE = '{original_default_role}'")
        conn.close()
        sys.exit(1)

    # =========================================================================
    # PHASE 3: VALIDATE CUSTOMER CONCERNS
    # =========================================================================
    banner("PHASE 3: VALIDATING CUSTOMER CONCERNS", "=")

    all_results = []

    # --- CONCERN 1 ---
    banner("CONCERN 1: 'Cannot give MCP server an explicit role'", "-")
    print('  Customer said: "A connection resolves to the user\'s default role')
    print('  and there is no way to pass a role per session or per call."')
    print()

    step(1, "Check which primary role the MCP session is using")
    r = mcp_sql(endpoint, headers, "SELECT CURRENT_ROLE() AS active_role", 10)
    data = extract_data(r)
    if data["ok"]:
        active_role = data["data"][0][0]
        result_ok(f"CURRENT_ROLE() = {active_role}")
        print()
        print(f"  RESOLUTION: The primary role is now {ROLE_MCP_ACCESS} — a narrow,")
        print("  least-privilege role. With 'session:role-any' in the token scope,")
        print("  the OAuth flow accepts whatever DEFAULT_ROLE is configured.")
        print("  You control the role PER USER via ALTER USER SET DEFAULT_ROLE.")
        all_results.append(("Concern 1: Explicit role control", active_role == ROLE_MCP_ACCESS))
    else:
        result_fail(data["error"])
        all_results.append(("Concern 1: Explicit role control", False))

    # --- CONCERN 2 ---
    banner("CONCERN 2: 'Secondary roles not usable on OAuth path'", "-")
    print('  Customer said: "USE ROLE is rejected and secondary roles are not')
    print('  usable either. This works differently via CLI but not on OAuth."')
    print()

    step(1, "Check if secondary roles are active in this OAuth/MCP session")
    r = mcp_sql(endpoint, headers, "SELECT CURRENT_ROLE() AS primary, CURRENT_SECONDARY_ROLES() AS secondary", 20)
    data = extract_data(r)
    c2_pass = False
    if data["ok"]:
        primary = data["data"][0][0]
        secondary_raw = data["data"][0][1]
        secondary = json.loads(secondary_raw)
        result_ok(f"Primary role: {primary}")
        result_ok(f"Secondary roles mode: {secondary['value']}")
        roles_list = secondary["roles"].split(",")
        result_ok(f"Active secondary roles ({len(roles_list)}): {', '.join(roles_list[:5])}...")
        print()

        has_finance = ROLE_FINANCE.upper() in [r.upper() for r in roles_list]
        has_marketing = ROLE_MARKETING.upper() in [r.upper() for r in roles_list]
        has_engineering = ROLE_ENGINEERING.upper() in [r.upper() for r in roles_list]

        if has_finance and has_marketing and has_engineering:
            result_ok(f"Domain roles confirmed active: {ROLE_FINANCE}, {ROLE_MARKETING}, {ROLE_ENGINEERING}")
            c2_pass = True
        print()
        print("  RESOLUTION: Secondary roles ARE active on the OAuth/MCP path.")
        print("  Set DEFAULT_SECONDARY_ROLES = ('ALL') on the user, and all")
        print("  granted roles activate as secondary roles in the session.")
    else:
        result_fail(data["error"])
    all_results.append(("Concern 2: Secondary roles on OAuth/MCP", c2_pass))

    step(2, "Confirm USE ROLE is blocked (governance guardrail)")
    r = mcp_sql(endpoint, headers, "USE ROLE ACCOUNTADMIN", 21)
    blocked = is_mcp_error(r)
    result_ok(f"USE ROLE ACCOUNTADMIN: blocked={blocked}")
    print("    (This is intentional — prevents privilege escalation inside session)")

    # --- CONCERN 3 ---
    banner("CONCERN 3: 'Result is an ever-growing default role'", "-")
    print('  Customer said: "Because the default role is the only role that has')
    print('  any effect, the pragmatic fix is to keep adding grants to it."')
    print()
    print(f"  Setup: {ROLE_MCP_ACCESS} has ZERO select grants on any table.")
    print(f"  Finance data is ONLY accessible via {ROLE_FINANCE}.")
    print(f"  Marketing data is ONLY accessible via {ROLE_MARKETING}.")
    print(f"  Engineering data is ONLY accessible via {ROLE_ENGINEERING}.")
    print()

    c3_pass = True

    step(1, "Query FINANCE data (requires DOMAIN_FINANCE secondary role)")
    r = mcp_sql(endpoint, headers, f"SELECT * FROM {DB}.{SCHEMA}.FINANCE_REVENUE", 30)
    data = extract_data(r)
    if data["ok"]:
        result_ok(f"Columns: {data['columns']}")
        for row in data["data"]:
            result_ok(f"  {row}")
    else:
        result_fail(data["error"])
        c3_pass = False

    step(2, "Query MARKETING data (requires DOMAIN_MARKETING secondary role)")
    r = mcp_sql(endpoint, headers, f"SELECT * FROM {DB}.{SCHEMA}.MARKETING_CAMPAIGNS", 31)
    data = extract_data(r)
    if data["ok"]:
        result_ok(f"Columns: {data['columns']}")
        for row in data["data"]:
            result_ok(f"  {row}")
    else:
        result_fail(data["error"])
        c3_pass = False

    step(3, "Query ENGINEERING data (requires DOMAIN_ENGINEERING secondary role)")
    r = mcp_sql(endpoint, headers, f"SELECT * FROM {DB}.{SCHEMA}.ENGINEERING_INCIDENTS", 32)
    data = extract_data(r)
    if data["ok"]:
        result_ok(f"Columns: {data['columns']}")
        for row in data["data"]:
            result_ok(f"  {row}")
    else:
        result_fail(data["error"])
        c3_pass = False

    print()
    print("  RESOLUTION: The default role stays NARROW. Cross-domain access comes")
    print("  from secondary roles. Each domain grants access to its own role.")
    print("  The default role NEVER needs to grow.")
    all_results.append(("Concern 3: No ever-growing default role", c3_pass))

    # --- CONCERN 4 ---
    banner("CONCERN 4: 'Does not scale across domains'", "-")
    print('  Customer said: "Different data domains need different roles. With the')
    print('  current design that means one MCP server per role."')
    print()

    step(1, "Cross-domain query through a SINGLE MCP server")
    r = mcp_sql(endpoint, headers, f"""
        SELECT 'Finance' AS domain, quarter AS detail, revenue AS value
        FROM {DB}.{SCHEMA}.FINANCE_REVENUE WHERE region = 'EMEA'
        UNION ALL
        SELECT 'Marketing' AS domain, campaign AS detail, spend AS value
        FROM {DB}.{SCHEMA}.MARKETING_CAMPAIGNS WHERE campaign = 'Product-Launch'
        UNION ALL
        SELECT 'Engineering' AS domain, severity AS detail, count AS value
        FROM {DB}.{SCHEMA}.ENGINEERING_INCIDENTS WHERE severity = 'P1'
    """, 40)
    data = extract_data(r)
    c4_pass = False
    if data["ok"]:
        result_ok(f"Columns: {data['columns']}")
        for row in data["data"]:
            result_ok(f"  {row}")
        c4_pass = True
    else:
        result_fail(data["error"])

    print()
    print("  RESOLUTION: ONE MCP server serves ALL domains. Domain isolation is")
    print("  handled by RBAC grants to secondary roles, not by MCP topology.")
    print("  Adding a new domain = create role + grant + assign to users.")
    all_results.append(("Concern 4: One server, multiple domains", c4_pass))

    # =========================================================================
    # FINAL SUMMARY
    # =========================================================================
    banner("FINAL RESULTS", "=")

    for label, passed in all_results:
        icon = "PASS" if passed else "FAIL"
        print(f"  [{icon}] {label}")

    print()
    print("-" * 70)
    print("  ARCHITECTURE USED:")
    print("-" * 70)
    print()
    print("  External OAuth Integration:")
    print(f"    EXTERNAL_OAUTH_ANY_ROLE_MODE = ENABLE")
    print()
    print("  Schema-level parameters (NEW - Jul 2026):")
    print(f"    OAUTH_AUTHORIZATION_SERVER = {INTEGRATION}")
    print(f"    OAUTH_SCOPES_SUPPORTED = 'session:role-any'")
    print()
    print("  Per-user configuration:")
    print(f"    DEFAULT_ROLE = {ROLE_MCP_ACCESS} (narrow: only MCP server USAGE)")
    print(f"    DEFAULT_SECONDARY_ROLES = ('ALL')")
    print()
    print("  Domain access model:")
    print(f"    {ROLE_FINANCE}    -> SELECT on finance tables")
    print(f"    {ROLE_MARKETING}  -> SELECT on marketing tables")
    print(f"    {ROLE_ENGINEERING} -> SELECT on engineering tables")
    print()
    print("  Result: Users get cross-domain access through ONE MCP server")
    print("  without bloating the default role or deploying multiple servers.")
    print()
    print("=" * 70)

    # Restore user's original default role
    cur.execute(f"ALTER USER {username} SET DEFAULT_ROLE = '{original_default_role}'")
    print(f"\n  (Restored DEFAULT_ROLE to {original_default_role})")
    conn.close()

    sys.exit(0 if all(p for _, p in all_results) else 1)


# ---------------------------------------------------------------------------
# --agent-test mode: mint token and print MCP config for Claude/MCP clients
# ---------------------------------------------------------------------------

def agent_test_mode():
    """Ensure integration exists, mint a 10-min token, print MCP client config."""
    if not ACCOUNT_URL:
        print("ERROR: Set SNOWFLAKE_ACCOUNT_URL environment variable.")
        sys.exit(1)

    conn = snowflake.connector.connect(connection_name=CONN_NAME)
    cur = conn.cursor()

    # Get user info
    cur.execute("SELECT CURRENT_USER()")
    username = cur.fetchone()[0]
    cur.execute(f"DESCRIBE USER {username}")
    user_props = {r[0]: r[1] for r in cur.fetchall()}
    login_name = user_props["LOGIN_NAME"]
    original_default_role = user_props["DEFAULT_ROLE"]

    cur.execute("USE ROLE ACCOUNTADMIN")

    # Generate RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    pub_b64 = base64.b64encode(public_der).decode()

    # Ensure database/schema exist
    cur.execute(f"CREATE DATABASE IF NOT EXISTS {DB}")
    cur.execute(f"CREATE SCHEMA IF NOT EXISTS {DB}.{SCHEMA}")

    # Create/replace integration
    cur.execute(f"""CREATE OR REPLACE SECURITY INTEGRATION {INTEGRATION}
        TYPE = EXTERNAL_OAUTH
        ENABLED = TRUE
        EXTERNAL_OAUTH_TYPE = CUSTOM
        EXTERNAL_OAUTH_ISSUER = '{ISSUER}'
        EXTERNAL_OAUTH_RSA_PUBLIC_KEY = '{pub_b64}'
        EXTERNAL_OAUTH_TOKEN_USER_MAPPING_CLAIM = 'name'
        EXTERNAL_OAUTH_SNOWFLAKE_USER_MAPPING_ATTRIBUTE = 'login_name'
        EXTERNAL_OAUTH_SCOPE_MAPPING_ATTRIBUTE = 'scp'
        EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE'
        EXTERNAL_OAUTH_AUDIENCE_LIST = ('{ACCOUNT_URL}')""")

    # Ensure MCP server exists
    cur.execute(f"""CREATE MCP SERVER IF NOT EXISTS {DB}.{SCHEMA}.{MCP_SERVER}
        FROM SPECIFICATION $$
        tools:
          - title: "SQL Execution"
            name: "sql-exec-tool"
            type: "SYSTEM_EXECUTE_SQL"
            description: "Execute SQL queries against Snowflake"
        $$""")

    # Ensure MCP access role exists and has grants
    cur.execute(f"CREATE ROLE IF NOT EXISTS {ROLE_MCP_ACCESS}")
    cur.execute(f"GRANT ROLE {ROLE_MCP_ACCESS} TO USER {username}")
    cur.execute(f"GRANT USAGE ON DATABASE {DB} TO ROLE {ROLE_MCP_ACCESS}")
    cur.execute(f"GRANT USAGE ON SCHEMA {DB}.{SCHEMA} TO ROLE {ROLE_MCP_ACCESS}")
    cur.execute(f"GRANT USAGE ON MCP SERVER {DB}.{SCHEMA}.{MCP_SERVER} TO ROLE {ROLE_MCP_ACCESS}")

    # Set parameters on schema
    cur.execute(f"""ALTER SCHEMA {DB}.{SCHEMA}
        SET OAUTH_AUTHORIZATION_SERVER = {INTEGRATION}
            OAUTH_SCOPES_SUPPORTED = 'session:role-any'""")

    # Set user default role
    cur.execute(f"ALTER USER {username} SET DEFAULT_ROLE = '{ROLE_MCP_ACCESS}' DEFAULT_SECONDARY_ROLES = ('ALL')")

    # Network rule for caller IP
    try:
        with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=5) as resp:
            my_ip = resp.read().decode().strip()
        cur.execute(f"""CREATE NETWORK RULE IF NOT EXISTS {DB}.{SCHEMA}.DEMO_INGRESS
            MODE = INGRESS TYPE = IPV4 VALUE_LIST = ('{my_ip}')""")
        cur.execute("SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT")
        policy_row = cur.fetchone()
        if policy_row and policy_row[1]:
            try:
                cur.execute(f"ALTER NETWORK POLICY {policy_row[1]} ADD ALLOWED_NETWORK_RULE_LIST = ('{DB}.{SCHEMA}.DEMO_INGRESS')")
            except Exception:
                pass
    except Exception:
        my_ip = "unknown"

    # Mint 10-minute token
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=10)
    token = jwt.encode({
        "iss": ISSUER,
        "aud": ACCOUNT_URL,
        "scp": "session:role-any",
        "name": login_name,
        "iat": now,
        "exp": exp,
    }, private_pem, algorithm="RS256")

    mcp_url = f"{ACCOUNT_URL}/api/v2/databases/{DB}/schemas/{SCHEMA}/mcp-servers/{MCP_SERVER}"

    # Restore original default role note
    print()
    print("=" * 70)
    print("  MCP AGENT TEST: External OAuth Token + Configuration")
    print("=" * 70)
    print()
    print(f"  User:           {username}")
    print(f"  Login name:     {login_name}")
    print(f"  Primary role:   {ROLE_MCP_ACCESS}")
    print(f"  Secondary roles: ALL (all granted roles active)")
    print(f"  Token expires:  {exp.strftime('%Y-%m-%d %H:%M:%S UTC')} (10 minutes)")
    print(f"  Your IP:        {my_ip}")
    print()
    print("-" * 70)
    print("  MCP SERVER URL:")
    print("-" * 70)
    print()
    print(f"  {mcp_url}")
    print()
    print("-" * 70)
    print("  BEARER TOKEN (valid 10 minutes):")
    print("-" * 70)
    print()
    print(f"  {token}")
    print()
    print("-" * 70)
    print("  CLAUDE CODE MCP CONFIG (~/.claude/claude_desktop_config.json):")
    print("-" * 70)
    print()
    config = {
        "mcpServers": {
            "snowflake-demo": {
                "url": mcp_url,
                "headers": {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
            }
        }
    }
    print(json.dumps(config, indent=2))
    print()
    print("-" * 70)
    print("  CURL TEST:")
    print("-" * 70)
    print()
    print(f"  curl -s -X POST '{mcp_url}' \\")
    print(f"    -H 'Content-Type: application/json' \\")
    print(f"    -H 'Accept: application/json' \\")
    print(f"    -H 'Authorization: Bearer {token[:50]}...' \\")
    print(f"    -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}' | python -m json.tool")
    print()
    print("=" * 70)
    print(f"  Token expires in 10 minutes. Re-run with --agent-test to get a new one.")
    print(f"  To restore your DEFAULT_ROLE afterward: ALTER USER {username} SET DEFAULT_ROLE = '{original_default_role}';")
    print("=" * 70)
    print()

    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MCP External OAuth Multi-Role Demo")
    parser.add_argument("--agent-test", action="store_true",
                        help="Mint a 10-min token and print MCP config for Claude/MCP clients")
    args = parser.parse_args()

    if args.agent_test:
        agent_test_mode()
    else:
        main()
