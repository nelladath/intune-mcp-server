"""
Entra ID (Azure AD) Device Management Tools
Device operations including search, delete, and management.
"""

from typing import Any
from ..graph_client import get_graph_client


async def list_entra_devices(top: int = 50, filter_query: str = "") -> dict[str, Any]:
    """
    List all devices registered in Entra ID (Azure AD).
    
    Args:
        top: Maximum number of devices to return
        filter_query: OData filter query
    
    Returns:
        List of Entra ID devices
    """
    client = get_graph_client()
    
    endpoint = f"/devices?$top={top}"
    if filter_query:
        endpoint += f"&$filter={filter_query}"
    
    response = await client.get(endpoint)
    devices = response.get("value", [])
    
    return {
        "count": len(devices),
        "devices": [
            {
                "id": d.get("id"),
                "displayName": d.get("displayName"),
                "deviceId": d.get("deviceId"),
                "operatingSystem": d.get("operatingSystem"),
                "operatingSystemVersion": d.get("operatingSystemVersion"),
                "trustType": d.get("trustType"),
                "isManaged": d.get("isManaged"),
                "isCompliant": d.get("isCompliant"),
                "registrationDateTime": d.get("registrationDateTime"),
                "approximateLastSignInDateTime": d.get("approximateLastSignInDateTime"),
            }
            for d in devices
        ]
    }


async def search_entra_devices(search_term: str) -> dict[str, Any]:
    """
    Search for devices in Entra ID by display name.
    
    Args:
        search_term: Device name to search for
    
    Returns:
        List of matching devices
    """
    client = get_graph_client()
    
    response = await client.get(f"/devices?$filter=displayName eq '{search_term}'")
    devices = response.get("value", [])
    
    return {
        "search_term": search_term,
        "count": len(devices),
        "devices": [
            {
                "id": d.get("id"),
                "displayName": d.get("displayName"),
                "deviceId": d.get("deviceId"),
                "operatingSystem": d.get("operatingSystem"),
                "trustType": d.get("trustType"),
                "isManaged": d.get("isManaged"),
            }
            for d in devices
        ]
    }


async def get_entra_device(device_id: str) -> dict[str, Any]:
    """
    Get details of a specific Entra ID device.
    
    Args:
        device_id: The Entra ID device object ID
    
    Returns:
        Device details
    """
    client = get_graph_client()
    
    device = await client.get(f"/devices/{device_id}")
    
    return {
        "id": device.get("id"),
        "displayName": device.get("displayName"),
        "deviceId": device.get("deviceId"),
        "operatingSystem": device.get("operatingSystem"),
        "operatingSystemVersion": device.get("operatingSystemVersion"),
        "trustType": device.get("trustType"),
        "isManaged": device.get("isManaged"),
        "isCompliant": device.get("isCompliant"),
        "mdmAppId": device.get("mdmAppId"),
        "registrationDateTime": device.get("registrationDateTime"),
        "approximateLastSignInDateTime": device.get("approximateLastSignInDateTime"),
        "accountEnabled": device.get("accountEnabled"),
        "manufacturer": device.get("manufacturer"),
        "model": device.get("model"),
    }


async def delete_entra_device(device_name: str = None, device_id: str = None, confirm: bool = False) -> dict[str, Any]:
    """
    Delete a device from Entra ID (Azure AD).
    
    Args:
        device_name: The device display name (will search and delete)
        device_id: The Entra ID device object ID (direct delete)
        confirm: Must be True to execute deletion
    
    Returns:
        Deletion status
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "⚠️ DELETE will remove the device from Entra ID! Set confirm=True to proceed."
        }
    
    if not device_name and not device_id:
        return {
            "status": "error",
            "message": "Either device_name or device_id must be provided"
        }
    
    client = get_graph_client()
    
    # If device_name provided, search for it first
    if device_name and not device_id:
        response = await client.get(f"/devices?$filter=displayName eq '{device_name}'")
        devices = response.get("value", [])
        
        if not devices:
            return {
                "status": "error",
                "message": f"No device found in Entra ID with name '{device_name}'"
            }
        
        if len(devices) > 1:
            return {
                "status": "error",
                "message": f"Multiple devices found with name '{device_name}'. Please use device_id instead.",
                "devices": [{"id": d.get("id"), "displayName": d.get("displayName")} for d in devices]
            }
        
        device_id = devices[0].get("id")
        device_name = devices[0].get("displayName")
    
    # Get device info before deletion
    if not device_name:
        try:
            device = await client.get(f"/devices/{device_id}")
            device_name = device.get("displayName", "Unknown")
        except:
            device_name = "Unknown"
    
    # Delete the device
    await client.delete(f"/devices/{device_id}")
    
    return {
        "status": "success",
        "message": f"Device '{device_name}' deleted from Entra ID",
        "device_id": device_id
    }


async def delete_intune_device(device_name: str = None, device_id: str = None, confirm: bool = False) -> dict[str, Any]:
    """
    Delete a device from Intune (not just retire, but fully delete the record).
    
    Args:
        device_name: The device display name (will search and delete)
        device_id: The Intune managed device ID (direct delete)
        confirm: Must be True to execute deletion
    
    Returns:
        Deletion status
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "⚠️ DELETE will remove the device record from Intune! Set confirm=True to proceed."
        }
    
    if not device_name and not device_id:
        return {
            "status": "error",
            "message": "Either device_name or device_id must be provided"
        }
    
    client = get_graph_client()
    
    # If device_name provided, search for it first
    if device_name and not device_id:
        response = await client.get(f"/deviceManagement/managedDevices?$filter=deviceName eq '{device_name}'")
        devices = response.get("value", [])
        
        if not devices:
            return {
                "status": "error",
                "message": f"No device found in Intune with name '{device_name}'"
            }
        
        if len(devices) > 1:
            return {
                "status": "error",
                "message": f"Multiple devices found with name '{device_name}'. Please use device_id instead.",
                "devices": [{"id": d.get("id"), "deviceName": d.get("deviceName")} for d in devices]
            }
        
        device_id = devices[0].get("id")
        device_name = devices[0].get("deviceName")
    
    # Get device info before deletion
    if not device_name:
        try:
            device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
            device_name = device.get("deviceName", "Unknown")
        except:
            device_name = "Unknown"
    
    # Delete the device
    await client.delete(f"/deviceManagement/managedDevices/{device_id}")
    
    return {
        "status": "success",
        "message": f"Device '{device_name}' deleted from Intune",
        "device_id": device_id
    }


async def delete_device_from_all(device_name: str, confirm: bool = False) -> dict[str, Any]:
    """
    Delete a device from both Intune and Entra ID.
    
    Args:
        device_name: The device display name
        confirm: Must be True to execute deletion
    
    Returns:
        Deletion status for both platforms
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "⚠️ DELETE will remove the device from BOTH Intune AND Entra ID! Set confirm=True to proceed."
        }
    
    results = {
        "device_name": device_name,
        "intune": None,
        "entra_id": None
    }
    
    # Delete from Intune first
    try:
        intune_result = await delete_intune_device(device_name=device_name, confirm=True)
        results["intune"] = intune_result
    except Exception as e:
        results["intune"] = {"status": "error", "message": str(e)}
    
    # Then delete from Entra ID
    try:
        entra_result = await delete_entra_device(device_name=device_name, confirm=True)
        results["entra_id"] = entra_result
    except Exception as e:
        results["entra_id"] = {"status": "error", "message": str(e)}
    
    # Determine overall status
    intune_success = results["intune"] and results["intune"].get("status") == "success"
    entra_success = results["entra_id"] and results["entra_id"].get("status") == "success"
    
    if intune_success and entra_success:
        results["status"] = "success"
        results["message"] = f"Device '{device_name}' deleted from both Intune and Entra ID"
    elif intune_success or entra_success:
        results["status"] = "partial_success"
        results["message"] = f"Device '{device_name}' partially deleted - check individual results"
    else:
        results["status"] = "error"
        results["message"] = f"Failed to delete device '{device_name}'"
    
    return results


async def disable_entra_device(device_id: str) -> dict[str, Any]:
    """
    Disable a device in Entra ID.
    
    Args:
        device_id: The Entra ID device object ID
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    device = await client.get(f"/devices/{device_id}?$select=displayName")
    
    await client.patch(f"/devices/{device_id}", json={"accountEnabled": False})
    
    return {
        "status": "success",
        "message": f"Device '{device.get('displayName')}' disabled in Entra ID"
    }


async def enable_entra_device(device_id: str) -> dict[str, Any]:
    """
    Enable a device in Entra ID.
    
    Args:
        device_id: The Entra ID device object ID
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    device = await client.get(f"/devices/{device_id}?$select=displayName")
    
    await client.patch(f"/devices/{device_id}", json={"accountEnabled": True})
    
    return {
        "status": "success",
        "message": f"Device '{device.get('displayName')}' enabled in Entra ID"
    }

