import asyncio
from intune_mcp_server.graph_client import get_graph_client

async def main():
    client = get_graph_client()
    device_id = "b54e562e-5944-49bd-a518-f90c0d3bdc73"
    
    # Get device info first
    try:
        device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
        print(f"Found Device: {device.get('deviceName')}")
        print(f"  Status: {device.get('managementState')}")
        
        # Delete the device
        await client.delete(f"/deviceManagement/managedDevices/{device_id}")
        print(f"  Result: DELETED from Intune")
    except Exception as e:
        print(f"Error: {e}")

asyncio.run(main())
