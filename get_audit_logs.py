import asyncio
from datetime import datetime, timedelta
from intune_mcp_server.graph_client import get_graph_client

async def main():
    client = get_graph_client()
    
    # Get audit logs from last 7 days
    cutoff = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    response = await client.get(f"/auditLogs/directoryAudits?$filter=activityDateTime ge {cutoff}&$top=20&$orderby=activityDateTime desc")
    logs = response.get("value", [])
    
    print(f"Recent Audit Logs ({len(logs)} entries)")
    print("=" * 80)
    
    for log in logs:
        print(f"Activity: {log.get('activityDisplayName')}")
        print(f"  Time: {log.get('activityDateTime')}")
        print(f"  Category: {log.get('category')}")
        print(f"  Result: {log.get('result')}")
        initiated = log.get("initiatedBy", {})
        user = initiated.get("user", {})
        app = initiated.get("app", {})
        if user:
            print(f"  Initiated By: {user.get('userPrincipalName', 'N/A')}")
        if app:
            print(f"  App: {app.get('displayName', 'N/A')}")
        targets = log.get("targetResources", [])
        for t in targets:
            print(f"  Target: {t.get('displayName', 'N/A')} ({t.get('type', 'N/A')})")
        print("-" * 80)

asyncio.run(main())
