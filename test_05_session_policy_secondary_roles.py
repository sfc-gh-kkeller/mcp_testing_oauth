"""Test: Session policy BLOCKED_SECONDARY_ROLES vs ALLOWED_SECONDARY_ROLES for MCP access."""
import json, base64, time, urllib.request, urllib.error
from datetime import datetime, timedelta, timezone
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import snowflake.connector

ACCOUNT_URL = "https://<orgname>-<account_name>.snowflakecomputing.com"
ISSUER = "https://mcp-demo-issuer.example.com"
DB = "MCP_DEMO_DB"
SCHEMA = "MULTI_ROLE_TEST"

conn = snowflake.connector.connect(connection_name="default")
cur = conn.cursor()
cur.execute("USE ROLE ACCOUNTADMIN")
cur.execute("DESCRIBE USER <USERNAME>")
login_name = next(r[1] for r in cur.fetchall() if r[0] == "LOGIN_NAME")

pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pem = pk.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
pub = base64.b64encode(pk.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
cur.execute(f"""CREATE OR REPLACE SECURITY INTEGRATION MCP_EXT_OAUTH_DEMO
    TYPE = EXTERNAL_OAUTH ENABLED = TRUE EXTERNAL_OAUTH_TYPE = CUSTOM
    EXTERNAL_OAUTH_ISSUER = '{ISSUER}' EXTERNAL_OAUTH_RSA_PUBLIC_KEY = '{pub}'
    EXTERNAL_OAUTH_TOKEN_USER_MAPPING_CLAIM = 'name'
    EXTERNAL_OAUTH_SNOWFLAKE_USER_MAPPING_ATTRIBUTE = 'login_name'
    EXTERNAL_OAUTH_SCOPE_MAPPING_ATTRIBUTE = 'scp'
    EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE'
    EXTERNAL_OAUTH_AUDIENCE_LIST = ('{ACCOUNT_URL}')""")
cur.execute(f"""ALTER SCHEMA {DB}.{SCHEMA} SET OAUTH_AUTHORIZATION_SERVER = MCP_EXT_OAUTH_DEMO
    OAUTH_SCOPES_SUPPORTED = 'session:role-any'""")
cur.execute("ALTER USER <USERNAME> SET DEFAULT_SECONDARY_ROLES = ('ALL')")

now = datetime.now(timezone.utc)
endpoint_owner = f"{ACCOUNT_URL}/api/v2/databases/{DB}/schemas/{SCHEMA}/mcp-servers/OWNER_TEST_MCP"
endpoint_demo = f"{ACCOUNT_URL}/api/v2/databases/{DB}/schemas/{SCHEMA}/mcp-servers/DEMO_MCP_SERVER"


def mcp_test(endpoint, role_hdr, label):
    token = jwt.encode({"iss": ISSUER, "aud": ACCOUNT_URL, "scp": "session:role-any",
                        "name": login_name, "iat": now, "exp": now + timedelta(hours=1)}, pem, algorithm="RS256")
    hdrs = {"Content-Type": "application/json", "Accept": "application/json",
            "Authorization": f"Bearer {token}", "X-Snowflake-Role": role_hdr}
    data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
    req = urllib.request.Request(endpoint, data=data, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            r = json.loads(resp.read().decode())
            return "BLOCKED" if "error" in r else "ACCESSIBLE"
    except urllib.error.HTTPError:
        return "BLOCKED"


def check_secondary(role_hdr):
    token = jwt.encode({"iss": ISSUER, "aud": ACCOUNT_URL, "scp": "session:role-any",
                        "name": login_name, "iat": now, "exp": now + timedelta(hours=1)}, pem, algorithm="RS256")
    hdrs = {"Content-Type": "application/json", "Accept": "application/json",
            "Authorization": f"Bearer {token}", "X-Snowflake-Role": role_hdr}
    data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "sql-exec-tool", "arguments": {"sql": "SELECT CURRENT_SECONDARY_ROLES() AS sec"}}}).encode()
    req = urllib.request.Request(endpoint_demo, data=data, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            r = json.loads(resp.read().decode())
            txt = r["result"]["content"][0]["text"]
            parsed = json.loads(txt)
            sec = json.loads(parsed["result_set"]["data"][0][0])
            return sec["roles"]
    except Exception as e:
        return f"ERROR: {e}"


# Clean state
try:
    cur.execute("ALTER USER <USERNAME> UNSET SESSION POLICY")
except Exception:
    pass
time.sleep(1)

print("=" * 70)
print("  SESSION POLICY: ALLOWED vs BLOCKED SECONDARY ROLES")
print("  MCP owned by ROLE_MCP_OWNER, no USAGE to ROLE_NO_GRANTS")
print("=" * 70)
print()

# Baseline
print("BASELINE (no session policy, DEFAULT_SECONDARY_ROLES=ALL):")
print(f"  OWNER_TEST_MCP via ROLE_NO_GRANTS: {mcp_test(endpoint_owner, 'ROLE_NO_GRANTS', '')}")
roles = check_secondary("ROLE_NO_GRANTS")
has_owner = "ROLE_MCP_OWNER" in roles
print(f"  ROLE_MCP_OWNER in secondaries: {has_owner}")
print(f"  Secondary roles: {roles[:100]}...")
print()

# Test A: ALLOWED_SECONDARY_ROLES (exclude owner)
print("-" * 70)
print("TEST A: Session Policy ALLOWED_SECONDARY_ROLES = ('ROLE_NO_GRANTS', 'DEMO_DOMAIN_FINANCE')")
print("  (does NOT list ROLE_MCP_OWNER)")
cur.execute(f"""CREATE OR REPLACE SESSION POLICY {DB}.{SCHEMA}.TEST_POLICY_A
    ALLOWED_SECONDARY_ROLES = ('ROLE_NO_GRANTS', 'DEMO_DOMAIN_FINANCE')""")
try:
    cur.execute(f"ALTER USER <USERNAME> SET SESSION POLICY {DB}.{SCHEMA}.TEST_POLICY_A FORCE")
except Exception:
    cur.execute(f"ALTER USER <USERNAME> SET SESSION POLICY {DB}.{SCHEMA}.TEST_POLICY_A")
time.sleep(2)
print(f"  OWNER_TEST_MCP via ROLE_NO_GRANTS: {mcp_test(endpoint_owner, 'ROLE_NO_GRANTS', '')}")
roles_a = check_secondary("ROLE_NO_GRANTS")
print(f"  ROLE_MCP_OWNER in secondaries: {'ROLE_MCP_OWNER' in roles_a}")
print(f"  Secondary roles: {roles_a[:100]}")
cur.execute("ALTER USER <USERNAME> UNSET SESSION POLICY")
print()

# Test B: BLOCKED_SECONDARY_ROLES (explicitly block owner)
time.sleep(1)
print("-" * 70)
print("TEST B: Session Policy BLOCKED_SECONDARY_ROLES = ('ROLE_MCP_OWNER')")
print("  (explicitly blocks the owner role from being a secondary)")
cur.execute(f"""CREATE OR REPLACE SESSION POLICY {DB}.{SCHEMA}.TEST_POLICY_B
    BLOCKED_SECONDARY_ROLES = ('ROLE_MCP_OWNER')""")
try:
    cur.execute(f"ALTER USER <USERNAME> SET SESSION POLICY {DB}.{SCHEMA}.TEST_POLICY_B FORCE")
except Exception:
    cur.execute(f"ALTER USER <USERNAME> SET SESSION POLICY {DB}.{SCHEMA}.TEST_POLICY_B")
time.sleep(2)
print(f"  OWNER_TEST_MCP via ROLE_NO_GRANTS: {mcp_test(endpoint_owner, 'ROLE_NO_GRANTS', '')}")
roles_b = check_secondary("ROLE_NO_GRANTS")
print(f"  ROLE_MCP_OWNER in secondaries: {'ROLE_MCP_OWNER' in roles_b}")
print(f"  Secondary roles: {roles_b[:100]}")
cur.execute("ALTER USER <USERNAME> UNSET SESSION POLICY")
print()

# Test C: ALLOWED_SECONDARY_ROLES = () (block ALL secondary roles)
time.sleep(1)
print("-" * 70)
print("TEST C: Session Policy ALLOWED_SECONDARY_ROLES = () (disallow all)")
cur.execute(f"""CREATE OR REPLACE SESSION POLICY {DB}.{SCHEMA}.TEST_POLICY_C
    ALLOWED_SECONDARY_ROLES = ()""")
try:
    cur.execute(f"ALTER USER <USERNAME> SET SESSION POLICY {DB}.{SCHEMA}.TEST_POLICY_C FORCE")
except Exception:
    cur.execute(f"ALTER USER <USERNAME> SET SESSION POLICY {DB}.{SCHEMA}.TEST_POLICY_C")
time.sleep(2)
print(f"  OWNER_TEST_MCP via ROLE_NO_GRANTS: {mcp_test(endpoint_owner, 'ROLE_NO_GRANTS', '')}")
roles_c = check_secondary("ROLE_NO_GRANTS")
print(f"  Secondary roles: {roles_c or '(none)'}")
cur.execute("ALTER USER <USERNAME> UNSET SESSION POLICY")
print()

# Cleanup
cur.execute("ALTER USER <USERNAME> SET DEFAULT_ROLE = 'DOCKERTEST' DEFAULT_SECONDARY_ROLES = ('ALL')")
conn.close()

print("=" * 70)
print("  SUMMARY")
print("=" * 70)
