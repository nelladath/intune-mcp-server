import asyncio
from intune_mcp_server.graph_client import get_graph_client

async def main():
    client = get_graph_client()
    
    # Search for device in Azure AD
    response = await client.get("/devices?$filter=displayName eq 'ANKET_VM'")
    devices = response.get("value", [])
    
    if devices:
        for device in devices:
            print(f"Found Entra ID Device:")
            print(f"  ID: {device.get('id')}")
            print(f"  Name: {device.get('displayName')}")
            print(f"  Device ID: {device.get('deviceId')}")
            
            # Delete the device
            device_id = device.get("id")
            await client.delete(f"/devices/{device_id}")
            print(f"  Status: DELETED from Entra ID")
    else:
        print("No device found in Entra ID with name ANKET_VM")

asyncio.run(main())
