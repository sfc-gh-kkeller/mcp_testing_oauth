import os
import json
import urllib.request
import urllib.error
import snowflake.connector


def main():
    conn_name = os.getenv("SNOWFLAKE_CONNECTION_NAME", "default")
    print(f"Connecting to Snowflake (connection: {conn_name})...")
    conn = snowflake.connector.connect(connection_name=conn_name)
    cur = conn.cursor()

    db = os.getenv("MCP_DATABASE", "MY_DB")
    schema = os.getenv("MCP_SCHEMA", "MY_SCHEMA")
    mcp_server_name = os.getenv("MCP_SERVER_NAME", "MY_MCP_SERVER")
    token_udf = os.getenv("MCP_TOKEN_UDF", f"{db}.{schema}.generate_token_test")

    cur.execute(f"SELECT {token_udf}()")
    token = cur.fetchone()[0]
    print(f"External OAuth token generated ({len(token)} chars)")

    account_url = os.getenv("SNOWFLAKE_ACCOUNT_URL", "https://<account>.snowflakecomputing.com")
    mcp_endpoint = f"{account_url}/api/v2/databases/{db}/schemas/{schema}/mcp-servers/{mcp_server_name}"
    print(f"MCP endpoint: {mcp_endpoint}\n")

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }

    print("=" * 60)
    print("TEST 1: tools/list — discover tools via external OAuth")
    print("=" * 60)
    result1 = mcp_request(mcp_endpoint, headers, {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
    })
    print(json.dumps(result1, indent=2))

    print()
    print("=" * 60)
    print("TEST 2: tools/call — execute SQL via external OAuth")
    print("=" * 60)
    result2 = mcp_request(mcp_endpoint, headers, {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "sql-exec-tool",
            "arguments": {
                "sql": "SELECT CURRENT_USER() AS user, CURRENT_ROLE() AS role, 'MCP external OAuth test OK' AS message",
            },
        },
    })
    print(json.dumps(result2, indent=2))

    print()
    print("=" * 60)
    print("TEST 3: RBAC enforcement — revoke grant, expect denial")
    print("=" * 60)
    mcp_fqn = f"{db}.{schema}.{mcp_server_name}"
    role = os.getenv("MCP_TOKEN_ROLE", "DOCKERTEST")
    cur.execute(f"REVOKE USAGE ON MCP SERVER {mcp_fqn} FROM ROLE {role}")
    print(f"Revoked USAGE on {mcp_fqn} from {role}")

    result3 = mcp_request(mcp_endpoint, headers, {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/list",
    })
    print(json.dumps(result3, indent=2))

    cur.execute(f"GRANT USAGE ON MCP SERVER {mcp_fqn} TO ROLE {role}")
    print(f"Re-granted USAGE on {mcp_fqn} to {role}")

    conn.close()

    print()
    print("=" * 60)
    success1 = isinstance(result1, dict) and "http_error" not in result1 and "error" not in result1
    success2 = isinstance(result2, dict) and "http_error" not in result2 and "error" not in result2
    rbac_denied = isinstance(result3, dict) and "error" in result3
    if success1 and success2 and rbac_denied:
        print("RESULT: All tests PASSED — OAuth works, RBAC enforced")
    elif success1 and success2:
        print("RESULT: OAuth works but RBAC denial was NOT enforced (unexpected)")
    elif success1:
        print("RESULT: tools/list works but tools/call failed with external OAuth")
    else:
        print("RESULT: External OAuth tokens DO NOT work with managed MCP servers")
    print("=" * 60)


def mcp_request(endpoint, headers, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(endpoint, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return {"http_status": resp.status, **json.loads(resp.read().decode())}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = body
        return {"http_error": e.code, "response": parsed}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


if __name__ == "__main__":
    main()
