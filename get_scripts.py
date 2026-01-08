import asyncio
from intune_mcp_server.graph_client import get_graph_client

async def main():
    client = get_graph_client()
    response = await client.get("/deviceManagement/deviceManagementScripts")
    scripts = response.get("value", [])
    print(f"Total PowerShell Scripts: {len(scripts)}")
    print("=" * 60)
    for s in scripts:
        print(f"Name: {s.get('displayName')}")
        print(f"  ID: {s.get('id')}")
        print(f"  Description: {s.get('description')}")
        print(f"  Run As: {s.get('runAsAccount')}")
        print(f"  File: {s.get('fileName')}")
        print(f"  Created: {s.get('createdDateTime')}")
        print("-" * 60)

asyncio.run(main())
