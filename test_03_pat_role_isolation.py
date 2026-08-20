#!/usr/bin/env python3
"""
=============================================================================
  MCP Role Control via PAT (Programmatic Access Token)
=============================================================================

  Tests role isolation using PAT with ROLE_RESTRICTION on MCP servers.
  A PAT restricted to a role overrides DEFAULT_ROLE and disables secondary roles.

  HOW TO USE:
    pip install pyjwt cryptography snowflake-connector-python
    SNOWFLAKE_CONNECTION_NAME=<conn> SNOWFLAKE_ACCOUNT_URL=<url> python test_pat_isolation.py

  WHAT IT TESTS:
    - PAT restricted to DEMO_DOMAIN_FINANCE overrides DEFAULT_ROLE
    - Secondary roles are disabled (only PAT role's grants accessible)
    - Finance data accessible, marketing/engineering blocked

  EASY MODIFICATIONS:
    - Change PAT_ROLE to restrict to a different domain
    - Add tables/queries to test different access patterns
=============================================================================
"""

import os
import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone

import snowflake.connector


# ===========================================================================
# CONFIGURATION
# ===========================================================================

CONNECTION_NAME = os.getenv("SNOWFLAKE_CONNECTION_NAME", "default")
ACCOUNT_URL = os.getenv("SNOWFLAKE_ACCOUNT_URL", "https://<orgname>-<account_name>.snowflakecomputing.com")

DB = "MCP_DEMO_DB"
SCHEMA = "MULTI_ROLE_TEST"
MCP_SERVER = "DEMO_MCP_SERVER"
WAREHOUSE = os.getenv("SNOWFLAKE_WAREHOUSE", "S2")

PAT_USER = "MCP_PAT_TEST_USER"
PAT_ROLE = "DEMO_DOMAIN_FINANCE"  # <-- CHANGE THIS to test different roles

ROLES = ["DEMO_MCP_ACCESS", "DEMO_DOMAIN_FINANCE", "DEMO_DOMAIN_MARKETING", "DEMO_DOMAIN_ENGINEERING"]


# ===========================================================================
# HELPERS
# ===========================================================================

def mcp_call(endpoint, token, sql):
    """Call MCP server with PAT token."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "X-Snowflake-Authorization-Token-Type": "PROGRAMMATIC_ACCESS_TOKEN",
    }
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


# ===========================================================================
# SETUP
# ===========================================================================

def setup():
    """Create PAT infrastructure. Returns (pat_token, endpoint)."""
    if "<orgname>" in ACCOUNT_URL:
        print("ERROR: Set SNOWFLAKE_ACCOUNT_URL environment variable.")
        raise SystemExit(1)

    print("=" * 70)
    print("  SETUP: PAT with ROLE_RESTRICTION")
    print("=" * 70)
    print()

    conn = snowflake.connector.connect(connection_name=CONNECTION_NAME)
    cur = conn.cursor()
    cur.execute("USE ROLE ACCOUNTADMIN")

    cur.execute(f"CREATE DATABASE IF NOT EXISTS {DB}")
    cur.execute(f"CREATE SCHEMA IF NOT EXISTS {DB}.{SCHEMA}")

    # Roles
    cur.execute("SELECT CURRENT_USER()")
    username = cur.fetchone()[0]
    for role in ROLES:
        cur.execute(f"CREATE ROLE IF NOT EXISTS {role}")
        cur.execute(f"GRANT ROLE {role} TO USER {username}")
        cur.execute(f"GRANT USAGE ON DATABASE {DB} TO ROLE {role}")
        cur.execute(f"GRANT USAGE ON SCHEMA {DB}.{SCHEMA} TO ROLE {role}")
        cur.execute(f"GRANT USAGE ON WAREHOUSE {WAREHOUSE} TO ROLE {role}")

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

    # Service user + PAT
    cur.execute(f"CREATE USER IF NOT EXISTS {PAT_USER} TYPE=SERVICE DEFAULT_ROLE='{PAT_ROLE}' DEFAULT_WAREHOUSE='{WAREHOUSE}'")
    cur.execute(f"GRANT ROLE {PAT_ROLE} TO USER {PAT_USER}")
    cur.execute(f"GRANT ROLE DEMO_DOMAIN_MARKETING TO USER {PAT_USER}")
    cur.execute(f"GRANT ROLE DEMO_MCP_ACCESS TO USER {PAT_USER}")
    cur.execute(f"CREATE OR REPLACE AUTHENTICATION POLICY {DB}.{SCHEMA}.PAT_POLICY PAT_POLICY=(NETWORK_POLICY_EVALUATION=NOT_ENFORCED)")
    try:
        cur.execute(f"ALTER USER {PAT_USER} SET AUTHENTICATION POLICY {DB}.{SCHEMA}.PAT_POLICY")
    except Exception:
        pass
    try:
        cur.execute(f"ALTER USER {PAT_USER} REMOVE PROGRAMMATIC ACCESS TOKEN MCP_TEST_PAT")
    except Exception:
        pass
    cur.execute(f"ALTER USER {PAT_USER} ADD PROGRAMMATIC ACCESS TOKEN MCP_TEST_PAT ROLE_RESTRICTION = '{PAT_ROLE}' DAYS_TO_EXPIRY = 1")
    pat_token = cur.fetchone()[1]
    print(f"  [ok] PAT for {PAT_USER} (ROLE_RESTRICTION={PAT_ROLE})")

    conn.close()
    endpoint = f"{ACCOUNT_URL}/api/v2/databases/{DB}/schemas/{SCHEMA}/mcp-servers/{MCP_SERVER}"
    return pat_token, endpoint


# ===========================================================================
# TESTS
# ===========================================================================

def run_tests(pat_token, endpoint):
    print()
    print("=" * 70)
    print(f"  PAT TEST: ROLE_RESTRICTION = {PAT_ROLE}")
    print("=" * 70)
    print()
    print(f"  Token: {pat_token}")
    print()

    # Role check
    r = mcp_call(endpoint, pat_token, "SELECT CURRENT_ROLE() AS role, CURRENT_SECONDARY_ROLES() AS sec")
    if r["ok"] and "data" in r:
        sec = json.loads(r["data"][0][1])
        print(f"    CURRENT_ROLE: {r['data'][0][0]}")
        print(f"    SECONDARY:    {sec['roles'] or '(none)'}")
    else:
        print(f"    ERROR: {r.get('error', 'unknown')}")
    print()

    # Data access
    print("    Data access:")
    for table, label in [("FINANCE_REVENUE", "finance"), ("MARKETING_CAMPAIGNS", "marketing"), ("ENGINEERING_INCIDENTS", "engineering")]:
        r = mcp_call(endpoint, pat_token, f"SELECT * FROM {DB}.{SCHEMA}.{table} LIMIT 1")
        status = "ACCESSIBLE" if r["ok"] else "BLOCKED"
        expect = "finance" if PAT_ROLE == "DEMO_DOMAIN_FINANCE" else ("marketing" if PAT_ROLE == "DEMO_DOMAIN_MARKETING" else "engineering")
        icon = "PASS" if (status == "ACCESSIBLE") == (label == expect) else "FAIL"
        print(f"      [{icon}] {label:15s} {status}")
    print()

    # Curl for manual testing
    print("    Curl (copy-paste to reproduce):")
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "sql-exec-tool", "arguments": {"sql": "SELECT CURRENT_ROLE() AS role"}}})
    print(f'    curl -s -X POST \'{endpoint}\' -H "Content-Type: application/json" -H "Accept: application/json" -H "Authorization: Bearer {pat_token}" -H "X-Snowflake-Authorization-Token-Type: PROGRAMMATIC_ACCESS_TOKEN" -d \'{payload}\' | python3 -m json.tool')
    print()
    print("=" * 70)


if __name__ == "__main__":
    pat_token, endpoint = setup()
    run_tests(pat_token, endpoint)
