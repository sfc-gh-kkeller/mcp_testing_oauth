"""Test: Can a role access an MCP server it has no USAGE grant on, via secondary roles?"""
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

# Create two roles with NO inheritance between them
cur.execute("CREATE ROLE IF NOT EXISTS ROLE_MCP_OWNER")
cur.execute("CREATE ROLE IF NOT EXISTS ROLE_NO_GRANTS")
cur.execute("GRANT ROLE ROLE_MCP_OWNER TO USER <USERNAME>")
cur.execute("GRANT ROLE ROLE_NO_GRANTS TO USER <USERNAME>")
cur.execute(f"GRANT USAGE ON DATABASE {DB} TO ROLE ROLE_MCP_OWNER")
cur.execute(f"GRANT USAGE ON SCHEMA {DB}.{SCHEMA} TO ROLE ROLE_MCP_OWNER")
cur.execute(f"GRANT USAGE ON DATABASE {DB} TO ROLE ROLE_NO_GRANTS")
cur.execute(f"GRANT USAGE ON SCHEMA {DB}.{SCHEMA} TO ROLE ROLE_NO_GRANTS")
cur.execute(f"GRANT USAGE ON WAREHOUSE S2 TO ROLE ROLE_MCP_OWNER")
cur.execute(f"GRANT USAGE ON WAREHOUSE S2 TO ROLE ROLE_NO_GRANTS")
cur.execute(f"GRANT CREATE MCP SERVER ON SCHEMA {DB}.{SCHEMA} TO ROLE ROLE_MCP_OWNER")

# Create MCP server AS ROLE_MCP_OWNER (it becomes the owner)
cur.execute("USE ROLE ROLE_MCP_OWNER")
cur.execute(f"""CREATE OR REPLACE MCP SERVER {DB}.{SCHEMA}.OWNER_TEST_MCP
    FROM SPECIFICATION $$
    tools:
      - title: "SQL"
        name: "sql-exec-tool"
        type: "SYSTEM_EXECUTE_SQL"
        description: "SQL"
    $$""")

# Back to accountadmin to check grants
cur.execute("USE ROLE ACCOUNTADMIN")
cur.execute(f"SHOW GRANTS ON MCP SERVER {DB}.{SCHEMA}.OWNER_TEST_MCP")
grants = cur.fetchall()
print("GRANTS ON MCP SERVER OWNER_TEST_MCP:")
for g in grants:
    print(f"  {g[1]:12s} -> {g[5]} (role: {g[4]})")
print()

# Verify no hierarchy between the two roles
cur.execute("SHOW GRANTS TO ROLE ROLE_NO_GRANTS")
no_grants_roles = [(r[1], r[3]) for r in cur.fetchall() if r[1] == "USAGE" and "ROLE" in str(r[3])]
print(f"Role hierarchy for ROLE_NO_GRANTS: {no_grants_roles or 'NONE (no inherited roles)'}")
print()

# Get login_name
cur.execute("DESCRIBE USER <USERNAME>")
login_name = next(r[1] for r in cur.fetchall() if r[0] == "LOGIN_NAME")
now = datetime.now(timezone.utc)
endpoint = f"{ACCOUNT_URL}/api/v2/databases/{DB}/schemas/{SCHEMA}/mcp-servers/OWNER_TEST_MCP"


def call(scope, role_hdr, label):
    token = jwt.encode({"iss": ISSUER, "aud": ACCOUNT_URL, "scp": scope, "name": login_name,
                        "iat": now, "exp": now + timedelta(hours=1)}, pem, algorithm="RS256")
    hdrs = {"Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Bearer {token}"}
    if role_hdr:
        hdrs["X-Snowflake-Role"] = role_hdr
    data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
    req = urllib.request.Request(endpoint, data=data, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            r = json.loads(resp.read().decode())
            if "result" in r and "tools" in r["result"]:
                print(f"  {label}: ACCESSIBLE")
            else:
                print(f"  {label}: response={json.dumps(r)[:100]}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            msg = json.loads(body).get("message", "")[:80]
        except Exception:
            msg = body[:80]
        print(f"  {label}: BLOCKED ({msg})")


print("=" * 70)
print("SCENARIO: MCP server owned by ROLE_MCP_OWNER")
print("  NO explicit USAGE grant to ROLE_NO_GRANTS")
print("  Both roles granted to same user, no hierarchy between them")
print("=" * 70)
print()

# Test 1: With ALL secondary roles
cur.execute("ALTER USER <USERNAME> SET DEFAULT_SECONDARY_ROLES = ('ALL')")
time.sleep(1)
print("TEST 1: DEFAULT_SECONDARY_ROLES = ('ALL'), scope = session:role-any")
print("  (ROLE_MCP_OWNER is active as a secondary role)")
call("session:role-any", "ROLE_NO_GRANTS", "X-Snowflake-Role: ROLE_NO_GRANTS")
call("session:role-any", "ROLE_MCP_OWNER", "X-Snowflake-Role: ROLE_MCP_OWNER")
print()

# Test 2: Specific scope (disables secondary roles)
print("TEST 2: scope = session:role:ROLE_NO_GRANTS (secondaries DISABLED)")
call("session:role:ROLE_NO_GRANTS", "ROLE_NO_GRANTS", "X-Snowflake-Role: ROLE_NO_GRANTS")
print()

# Test 3: Disable secondary roles at user level
cur.execute("ALTER USER <USERNAME> SET DEFAULT_SECONDARY_ROLES = ()")
time.sleep(1)
print("TEST 3: DEFAULT_SECONDARY_ROLES = (), scope = session:role-any")
print("  (No secondary roles at all)")
call("session:role-any", "ROLE_NO_GRANTS", "X-Snowflake-Role: ROLE_NO_GRANTS")
call("session:role-any", "ROLE_MCP_OWNER", "X-Snowflake-Role: ROLE_MCP_OWNER")
print()

# Restore
cur.execute("ALTER USER <USERNAME> SET DEFAULT_ROLE = 'DOCKERTEST' DEFAULT_SECONDARY_ROLES = ('ALL')")
conn.close()

print("=" * 70)
print("EXPLANATION:")
print("  With DEFAULT_SECONDARY_ROLES = ALL + session:role-any:")
print("    ALL roles are active as secondaries, including ROLE_MCP_OWNER.")
print("    ROLE_MCP_OWNER has OWNERSHIP on the MCP server.")
print("    So the session has access via the secondary role, even though")
print("    ROLE_NO_GRANTS (the primary) has no USAGE grant.")
print()
print("  With session:role:X or DEFAULT_SECONDARY_ROLES = ():")
print("    Secondary roles are disabled. ROLE_NO_GRANTS alone cannot access")
print("    the MCP server because it has no USAGE grant.")
print("=" * 70)
