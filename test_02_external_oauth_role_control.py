#!/usr/bin/env python3
"""
=============================================================================
  MCP Role Control via External OAuth
=============================================================================

  Tests all External OAuth role control patterns with managed MCP servers:
    A. session:role-any (broad access, secondary roles active)
    B. session:role:X + X-Snowflake-Role header (per-request domain isolation)
    C. Session Policy ALLOWED_SECONDARY_ROLES (curated multi-domain)
    D. Token scp array (per-request role switching allowlist)

  HOW TO USE:
    pip install pyjwt cryptography snowflake-connector-python
    SNOWFLAKE_CONNECTION_NAME=<conn> SNOWFLAKE_ACCOUNT_URL=<url> python test_role_isolation.py

    Or with pixi:
    pixi install
    SNOWFLAKE_CONNECTION_NAME=<conn> SNOWFLAKE_ACCOUNT_URL=<url> pixi run python test_role_isolation.py

  PREREQUISITES:
    - A Snowflake connection in ~/.snowflake/connections.toml
    - ACCOUNTADMIN (to create integrations, roles, session policies)
    - SNOWFLAKE_ACCOUNT_URL env var set
=============================================================================
"""

import os
import json
import time
import base64
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import snowflake.connector


# ===========================================================================
# CONFIGURATION - Modify these to change test behavior
# ===========================================================================

CONNECTION_NAME = os.getenv("SNOWFLAKE_CONNECTION_NAME", "default")
ACCOUNT_URL = os.getenv("SNOWFLAKE_ACCOUNT_URL", "https://<orgname>-<account_name>.snowflakecomputing.com")

DB = "MCP_DEMO_DB"
SCHEMA = "MULTI_ROLE_TEST"
MCP_SERVER = "DEMO_MCP_SERVER"
WAREHOUSE = os.getenv("SNOWFLAKE_WAREHOUSE", "S2")

INTEGRATION_NAME = "MCP_EXT_OAUTH_DEMO"
ISSUER = "https://mcp-demo-issuer.example.com"
ADVERTISED_SCOPES = "session:role:DEMO_DOMAIN_FINANCE,session:role:DEMO_DOMAIN_MARKETING,session:role-any"

ROLES = ["DEMO_MCP_ACCESS", "DEMO_DOMAIN_FINANCE", "DEMO_DOMAIN_MARKETING", "DEMO_DOMAIN_ENGINEERING"]


# ===========================================================================
# HELPERS
# ===========================================================================

def mcp_call(endpoint, token, sql, token_type="oauth", role_header=None):
    """Call the MCP server's sql-exec-tool."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }
    if token_type == "pat":
        headers["X-Snowflake-Authorization-Token-Type"] = "PROGRAMMATIC_ACCESS_TOKEN"
    if role_header:
        headers["X-Snowflake-Role"] = role_header

    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "sql-exec-tool", "arguments": {"sql": sql}}}
    data = json.dumps(payload).encode()
    req = urllib.request.Request(endpoint, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            r = json.loads(resp.read().decode())
            content = r.get("result", {}).get("content", [{}])[0].get("text", "")
            if r.get("result", {}).get("isError", False):
                return {"ok": False, "error": content[:200]}
            try:
                parsed = json.loads(content)
                if "result_set" in parsed:
                    return {"ok": True, "data": parsed["result_set"]["data"],
                            "columns": [c["name"] for c in parsed["result_set"]["resultSetMetaData"]["rowType"]]}
            except (json.JSONDecodeError, KeyError):
                pass
            return {"ok": True, "raw": content[:200]}
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            err = json.loads(body)
            return {"ok": False, "error": f"HTTP {e.code}: {err.get('message', body)[:150]}"}
        except json.JSONDecodeError:
            return {"ok": False, "error": f"HTTP {e.code}: {body[:150]}"}


def print_curl(endpoint, token, sql, token_type="oauth", role_header=None):
    """Print a one-line curl command (full token, copy-pasteable)."""
    h = f'-H "Content-Type: application/json" -H "Accept: application/json" -H "Authorization: Bearer {token}"'
    if token_type == "pat":
        h += ' -H "X-Snowflake-Authorization-Token-Type: PROGRAMMATIC_ACCESS_TOKEN"'
    if role_header:
        h += f' -H "X-Snowflake-Role: {role_header}"'
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "sql-exec-tool", "arguments": {"sql": sql.strip()}}})
    print(f"    curl -s -X POST '{endpoint}' {h} -d '{payload}' | python3 -m json.tool")
    print()


def show(label, result, expect_ok=True):
    """Pretty-print a test result."""
    if result["ok"]:
        status = "PASS" if expect_ok else "UNEXPECTED"
        if "data" in result:
            print(f"    [{status}] {label}")
            for row in result["data"]:
                print(f"       -> {row}")
        else:
            print(f"    [{status}] {label}: {result.get('raw', 'OK')[:100]}")
    else:
        status = "PASS" if not expect_ok else "FAIL"
        print(f"    [{status}] {label}")
        print(f"       Error: {result['error'][:150]}")


def access_test(endpoint, token, token_type="oauth", role_header=None):
    """Run finance/marketing/engineering access tests, return dict of results."""
    results = {}
    for table, label in [("FINANCE_REVENUE", "finance"), ("MARKETING_CAMPAIGNS", "marketing"), ("ENGINEERING_INCIDENTS", "engineering")]:
        r = mcp_call(endpoint, token, f"SELECT * FROM {DB}.{SCHEMA}.{table} LIMIT 1", token_type, role_header)
        results[label] = "ACCESSIBLE" if r["ok"] else "BLOCKED"
    return results


# ===========================================================================
# SETUP
# ===========================================================================

def setup():
    """Create all infrastructure. Returns (private_pem, login_name, pat_token, endpoint, cur)."""
    if "<orgname>" in ACCOUNT_URL:
        print("ERROR: Set SNOWFLAKE_ACCOUNT_URL environment variable.")
        raise SystemExit(1)
    print("=" * 70)
    print("  SETUP")
    print("=" * 70)
    print()

    conn = snowflake.connector.connect(connection_name=CONNECTION_NAME)
    cur = conn.cursor()
    cur.execute("USE ROLE ACCOUNTADMIN")

    # RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
    pub_b64 = base64.b64encode(private_key.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    print("  [ok] RSA key pair generated")

    # DB/Schema
    cur.execute(f"CREATE DATABASE IF NOT EXISTS {DB}")
    cur.execute(f"CREATE SCHEMA IF NOT EXISTS {DB}.{SCHEMA}")

    # Integration
    cur.execute(f"""CREATE OR REPLACE SECURITY INTEGRATION {INTEGRATION_NAME}
        TYPE = EXTERNAL_OAUTH ENABLED = TRUE EXTERNAL_OAUTH_TYPE = CUSTOM
        EXTERNAL_OAUTH_ISSUER = '{ISSUER}'
        EXTERNAL_OAUTH_RSA_PUBLIC_KEY = '{pub_b64}'
        EXTERNAL_OAUTH_TOKEN_USER_MAPPING_CLAIM = 'name'
        EXTERNAL_OAUTH_SNOWFLAKE_USER_MAPPING_ATTRIBUTE = 'login_name'
        EXTERNAL_OAUTH_SCOPE_MAPPING_ATTRIBUTE = 'scp'
        EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE'
        EXTERNAL_OAUTH_AUDIENCE_LIST = ('{ACCOUNT_URL}')""")
    cur.execute(f"""ALTER SCHEMA {DB}.{SCHEMA} SET OAUTH_AUTHORIZATION_SERVER = {INTEGRATION_NAME}
        OAUTH_SCOPES_SUPPORTED = '{ADVERTISED_SCOPES}'""")
    print(f"  [ok] Integration + schema params")

    # Roles
    cur.execute("SELECT CURRENT_USER()")
    username = cur.fetchone()[0]
    for role in ROLES:
        cur.execute(f"CREATE ROLE IF NOT EXISTS {role}")
        cur.execute(f"GRANT ROLE {role} TO USER {username}")
        cur.execute(f"GRANT USAGE ON DATABASE {DB} TO ROLE {role}")
        cur.execute(f"GRANT USAGE ON SCHEMA {DB}.{SCHEMA} TO ROLE {role}")
        cur.execute(f"GRANT USAGE ON WAREHOUSE {WAREHOUSE} TO ROLE {role}")
    print(f"  [ok] Roles: {', '.join(ROLES)}")

    # MCP Server
    cur.execute(f"""CREATE OR REPLACE MCP SERVER {DB}.{SCHEMA}.{MCP_SERVER}
        FROM SPECIFICATION $$
        tools:
          - title: "SQL Execution"
            name: "sql-exec-tool"
            type: "SYSTEM_EXECUTE_SQL"
            description: "Execute SQL queries"
        $$""")
    for role in ROLES:
        cur.execute(f"GRANT USAGE ON MCP SERVER {DB}.{SCHEMA}.{MCP_SERVER} TO ROLE {role}")

    # Tables
    cur.execute(f"CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.FINANCE_REVENUE (quarter VARCHAR, revenue NUMBER, region VARCHAR)")
    cur.execute(f"TRUNCATE TABLE IF EXISTS {DB}.{SCHEMA}.FINANCE_REVENUE")
    cur.execute(f"INSERT INTO {DB}.{SCHEMA}.FINANCE_REVENUE VALUES ('Q1-2026',12500000,'EMEA'),('Q2-2026',14200000,'APAC'),('Q3-2026',11800000,'AMER')")
    cur.execute(f"GRANT SELECT ON TABLE {DB}.{SCHEMA}.FINANCE_REVENUE TO ROLE DEMO_DOMAIN_FINANCE")
    cur.execute(f"CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.MARKETING_CAMPAIGNS (campaign VARCHAR, spend NUMBER, leads INT)")
    cur.execute(f"TRUNCATE TABLE IF EXISTS {DB}.{SCHEMA}.MARKETING_CAMPAIGNS")
    cur.execute(f"INSERT INTO {DB}.{SCHEMA}.MARKETING_CAMPAIGNS VALUES ('Brand-Awareness',500000,12000),('Product-Launch',750000,8500)")
    cur.execute(f"GRANT SELECT ON TABLE {DB}.{SCHEMA}.MARKETING_CAMPAIGNS TO ROLE DEMO_DOMAIN_MARKETING")
    cur.execute(f"CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.ENGINEERING_INCIDENTS (severity VARCHAR, count INT, mttr_hours FLOAT)")
    cur.execute(f"TRUNCATE TABLE IF EXISTS {DB}.{SCHEMA}.ENGINEERING_INCIDENTS")
    cur.execute(f"INSERT INTO {DB}.{SCHEMA}.ENGINEERING_INCIDENTS VALUES ('P1',3,2.5),('P2',12,8.0),('P3',47,24.0)")
    cur.execute(f"GRANT SELECT ON TABLE {DB}.{SCHEMA}.ENGINEERING_INCIDENTS TO ROLE DEMO_DOMAIN_ENGINEERING")
    print("  [ok] Tables with domain-specific grants")

    # User config
    cur.execute(f"ALTER USER {username} SET DEFAULT_ROLE = 'DEMO_MCP_ACCESS' DEFAULT_SECONDARY_ROLES = ('ALL')")

    # Network rule
    try:
        with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=5) as resp:
            my_ip = resp.read().decode().strip()
        cur.execute(f"CREATE NETWORK RULE IF NOT EXISTS {DB}.{SCHEMA}.TEST_INGRESS MODE=INGRESS TYPE=IPV4 VALUE_LIST=('{my_ip}')")
        cur.execute("SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT")
        policy = cur.fetchone()
        if policy and policy[1]:
            try:
                cur.execute(f"ALTER NETWORK POLICY {policy[1]} ADD ALLOWED_NETWORK_RULE_LIST = ('{DB}.{SCHEMA}.TEST_INGRESS')")
            except Exception:
                pass
        print(f"  [ok] Network rule ({my_ip})")
    except Exception:
        pass

    # Login name for token claims
    cur.execute(f"DESCRIBE USER {username}")
    login_name = next(r[1] for r in cur.fetchall() if r[0] == "LOGIN_NAME")

    time.sleep(2)
    endpoint = f"{ACCOUNT_URL}/api/v2/databases/{DB}/schemas/{SCHEMA}/mcp-servers/{MCP_SERVER}"
    print(f"\n  Endpoint: {endpoint}\n")

    return private_pem, login_name, username, endpoint, cur


# ===========================================================================
# TEST SECTIONS
# ===========================================================================

def section_a(endpoint, private_pem, login_name):
    """External OAuth: session:role-any (broad access, all secondary roles)."""
    print("=" * 70)
    print("  SECTION A: External OAuth — session:role-any (broad access)")
    print("=" * 70)
    print()

    token = jwt.encode({"iss": ISSUER, "aud": ACCOUNT_URL, "scp": "session:role-any",
                        "name": login_name, "iat": datetime.now(timezone.utc),
                        "exp": datetime.now(timezone.utc) + timedelta(hours=24)}, private_pem, algorithm="RS256")
    print(f"  Token: {token}\n")

    r = mcp_call(endpoint, token, "SELECT CURRENT_ROLE() AS role, CURRENT_SECONDARY_ROLES() AS sec", role_header="DEMO_MCP_ACCESS")
    if r["ok"] and "data" in r:
        sec = json.loads(r["data"][0][1])
        print(f"    Role: {r['data'][0][0]}, Secondary: {sec['value']} ({len(sec['roles'].split(','))} roles)")
    print()

    access = access_test(endpoint, token, role_header="DEMO_MCP_ACCESS")
    for domain, status in access.items():
        print(f"    {domain:15s} {status}")
    print()


def section_b(endpoint, private_pem, login_name):
    """External OAuth: session:role:X + X-Snowflake-Role (per-request isolation)."""
    print("=" * 70)
    print("  SECTION B: session:role:X + X-Snowflake-Role header (isolation)")
    print("=" * 70)
    print()

    token = jwt.encode({"iss": ISSUER, "aud": ACCOUNT_URL, "scp": "session:role:DEMO_DOMAIN_FINANCE",
                        "name": login_name, "iat": datetime.now(timezone.utc),
                        "exp": datetime.now(timezone.utc) + timedelta(hours=24)}, private_pem, algorithm="RS256")
    print(f"  Token scope: session:role:DEMO_DOMAIN_FINANCE")
    print(f"  X-Snowflake-Role: DEMO_DOMAIN_FINANCE")
    print(f"  Token: {token}\n")

    r = mcp_call(endpoint, token, "SELECT CURRENT_ROLE() AS role, CURRENT_SECONDARY_ROLES() AS sec", role_header="DEMO_DOMAIN_FINANCE")
    if r["ok"] and "data" in r:
        sec = json.loads(r["data"][0][1])
        print(f"    Role: {r['data'][0][0]}, Secondary: {sec['roles'] or '(none)'}")
    elif not r["ok"]:
        print(f"    {r['error'][:150]}")
    print()

    print("    Data access:")
    access = access_test(endpoint, token, role_header="DEMO_DOMAIN_FINANCE")
    for domain, status in access.items():
        show(domain, {"ok": status == "ACCESSIBLE"} if status == "ACCESSIBLE" else {"ok": False, "error": "blocked"},
             expect_ok=(domain == "finance"))
    print()

    # Curl for manual reproduction
    print("  Curl (finance query):")
    print_curl(endpoint, token, f"SELECT * FROM {DB}.{SCHEMA}.FINANCE_REVENUE LIMIT 1", role_header="DEMO_DOMAIN_FINANCE")


def section_c(endpoint, private_pem, login_name, cur, username):
    """Session Policy ALLOWED_SECONDARY_ROLES (curated multi-domain)."""
    print("=" * 70)
    print("  SECTION C: Session Policy — ALLOWED_SECONDARY_ROLES (curated)")
    print("=" * 70)
    print()

    # Create and apply session policy
    cur.execute("USE ROLE ACCOUNTADMIN")
    cur.execute(f"""CREATE OR REPLACE SESSION POLICY {DB}.{SCHEMA}.LIMIT_SECONDARY
        ALLOWED_SECONDARY_ROLES = ('DEMO_DOMAIN_FINANCE', 'DEMO_DOMAIN_MARKETING')""")
    try:
        cur.execute(f"ALTER USER {username} SET SESSION POLICY {DB}.{SCHEMA}.LIMIT_SECONDARY FORCE")
    except Exception:
        cur.execute(f"ALTER USER {username} SET SESSION POLICY {DB}.{SCHEMA}.LIMIT_SECONDARY")
    time.sleep(1)

    token = jwt.encode({"iss": ISSUER, "aud": ACCOUNT_URL, "scp": "session:role-any",
                        "name": login_name, "iat": datetime.now(timezone.utc),
                        "exp": datetime.now(timezone.utc) + timedelta(hours=24)}, private_pem, algorithm="RS256")

    print("  Token scope: session:role-any")
    print("  Session Policy: ALLOWED_SECONDARY_ROLES = ('DEMO_DOMAIN_FINANCE', 'DEMO_DOMAIN_MARKETING')")
    print()

    r = mcp_call(endpoint, token, "SELECT CURRENT_ROLE() AS role, CURRENT_SECONDARY_ROLES() AS sec", role_header="DEMO_MCP_ACCESS")
    if r["ok"] and "data" in r:
        sec = json.loads(r["data"][0][1])
        print(f"    Role: {r['data'][0][0]}, Secondary: {sec['roles'] or '(none)'}")
    print()

    print("    Data access:")
    access = access_test(endpoint, token, role_header="DEMO_MCP_ACCESS")
    for domain, status in access.items():
        show(domain, {"ok": status == "ACCESSIBLE"} if status == "ACCESSIBLE" else {"ok": False, "error": "blocked"},
             expect_ok=(domain in ("finance", "marketing")))
    print()

    # Cleanup
    cur.execute(f"ALTER USER {username} UNSET SESSION POLICY")


def section_d(endpoint, private_pem, login_name):
    """Token scp array = per-request role switching allowlist."""
    print("=" * 70)
    print("  SECTION D: Token scp array (per-request role switching)")
    print("=" * 70)
    print()

    token = jwt.encode({"iss": ISSUER, "aud": ACCOUNT_URL,
                        "scp": ["session:role:DEMO_DOMAIN_FINANCE", "session:role:DEMO_DOMAIN_MARKETING"],
                        "name": login_name, "iat": datetime.now(timezone.utc),
                        "exp": datetime.now(timezone.utc) + timedelta(hours=24)}, private_pem, algorithm="RS256")

    print('  Token scp: ["session:role:DEMO_DOMAIN_FINANCE", "session:role:DEMO_DOMAIN_MARKETING"]')
    print()

    # Request as FINANCE
    print("  X-Snowflake-Role: DEMO_DOMAIN_FINANCE")
    r = mcp_call(endpoint, token, "SELECT CURRENT_ROLE() AS role", role_header="DEMO_DOMAIN_FINANCE")
    if r["ok"] and "data" in r:
        print(f"    Role: {r['data'][0][0]}")
    else:
        print(f"    {r.get('error', 'unknown')[:100]}")

    # Request as MARKETING (switch role, same token)
    print("  X-Snowflake-Role: DEMO_DOMAIN_MARKETING")
    r = mcp_call(endpoint, token, "SELECT CURRENT_ROLE() AS role", role_header="DEMO_DOMAIN_MARKETING")
    if r["ok"] and "data" in r:
        print(f"    Role: {r['data'][0][0]}")
    else:
        print(f"    {r.get('error', 'unknown')[:100]}")

    # Request as ENGINEERING (NOT in token array — should fail)
    print("  X-Snowflake-Role: DEMO_DOMAIN_ENGINEERING (not in token scope)")
    r = mcp_call(endpoint, token, "SELECT CURRENT_ROLE() AS role", role_header="DEMO_DOMAIN_ENGINEERING")
    if r["ok"]:
        print(f"    UNEXPECTED: {r}")
    else:
        print(f"    BLOCKED (as expected): {r['error'][:80]}")
    print()


# ===========================================================================
# MAIN
# ===========================================================================

if __name__ == "__main__":
    private_pem, login_name, username, endpoint, cur = setup()

    section_a(endpoint, private_pem, login_name)
    section_b(endpoint, private_pem, login_name)
    section_c(endpoint, private_pem, login_name, cur, username)
    section_d(endpoint, private_pem, login_name)

    # Restore
    cur.execute("USE ROLE ACCOUNTADMIN")
    cur.execute(f"ALTER USER {username} SET DEFAULT_ROLE = 'DOCKERTEST' DEFAULT_SECONDARY_ROLES = ('ALL')")
    cur.connection.close()

    print("=" * 70)
    print("  DONE — all sections complete. DEFAULT_ROLE restored.")
    print("=" * 70)
