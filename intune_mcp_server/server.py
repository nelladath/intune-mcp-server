#!/usr/bin/env python3
"""
Microsoft Graph MCP Server for Intune Management

A comprehensive MCP server that provides tools for managing Microsoft Intune
through the Microsoft Graph API.
"""

import asyncio
import sys
import os
from typing import Any

# Add parent directory to path for imports when running directly
if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP

from intune_mcp_server.config import get_config
from intune_mcp_server.graph_client import get_graph_client

# Create the MCP server instance using FastMCP
mcp = FastMCP("intune-mcp-server")


@mcp.tool()
async def test_connection() -> dict[str, Any]:
    """
    Test the connection to Microsoft Graph API.
    
    Returns connection status and tenant information.
    """
    try:
        client = get_graph_client()
        org = await client.get("/organization")
        org_info = org.get("value", [{}])[0]
        
        return {
            "status": "connected",
            "message": "Successfully connected to Microsoft Graph API",
            "tenant": {
                "displayName": org_info.get("displayName"),
                "id": org_info.get("id"),
            }
        }
    except Exception as e:
        return {"status": "error", "message": f"Failed to connect: {str(e)}"}


@mcp.tool()
async def get_intune_overview() -> dict[str, Any]:
    """
    Get an overview of the Intune environment including device counts and compliance summary.
    """
    client = get_graph_client()
    overview = {}
    
    try:
        devices = await client.get(
            "/deviceManagement/managedDevices?$select=complianceState,operatingSystem&$top=999"
        )
        device_list = devices.get("value", [])
        
        compliance_counts = {}
        os_counts = {}
        for d in device_list:
            state = d.get("complianceState", "unknown")
            os = d.get("operatingSystem", "unknown")
            compliance_counts[state] = compliance_counts.get(state, 0) + 1
            os_counts[os] = os_counts.get(os, 0) + 1
        
        overview["devices"] = {
            "total": len(device_list),
            "by_compliance": compliance_counts,
            "by_os": os_counts
        }
    except Exception as e:
        overview["devices"] = {"error": str(e)}
    
    return overview


# ============== DEVICE MANAGEMENT TOOLS ==============

@mcp.tool()
async def list_managed_devices(
    filter_query: str = "",
    top: int = 50
) -> dict[str, Any]:
    """
    List all Intune managed devices.
    
    Args:
        filter_query: OData filter (e.g., "operatingSystem eq 'Windows'")
        top: Maximum number of devices to return (default 50, max 1000)
    """
    client = get_graph_client()
    
    endpoint = "/deviceManagement/managedDevices"
    params = [f"$top={min(top, 1000)}"]
    if filter_query:
        params.append(f"$filter={filter_query}")
    endpoint += "?" + "&".join(params)
    
    response = await client.get(endpoint)
    devices = response.get("value", [])
    
    return {
        "count": len(devices),
        "devices": [
            {
                "id": d.get("id"),
                "deviceName": d.get("deviceName"),
                "userPrincipalName": d.get("userPrincipalName"),
                "operatingSystem": d.get("operatingSystem"),
                "osVersion": d.get("osVersion"),
                "complianceState": d.get("complianceState"),
                "lastSyncDateTime": d.get("lastSyncDateTime"),
                "serialNumber": d.get("serialNumber"),
            }
            for d in devices
        ]
    }


@mcp.tool()
async def get_device_details(device_id: str) -> dict[str, Any]:
    """
    Get comprehensive details for a specific managed device.
    
    Args:
        device_id: The Intune device ID
    """
    client = get_graph_client()
    device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
    
    # Get compliance policy states
    try:
        compliance = await client.get(
            f"/deviceManagement/managedDevices/{device_id}/deviceCompliancePolicyStates"
        )
        compliance_states = compliance.get("value", [])
    except:
        compliance_states = []
    
    return {
        "basic_info": {
            "id": device.get("id"),
            "deviceName": device.get("deviceName"),
            "userDisplayName": device.get("userDisplayName"),
            "userPrincipalName": device.get("userPrincipalName"),
        },
        "hardware": {
            "serialNumber": device.get("serialNumber"),
            "model": device.get("model"),
            "manufacturer": device.get("manufacturer"),
            "totalStorageSpaceInBytes": device.get("totalStorageSpaceInBytes"),
            "freeStorageSpaceInBytes": device.get("freeStorageSpaceInBytes"),
        },
        "os_info": {
            "operatingSystem": device.get("operatingSystem"),
            "osVersion": device.get("osVersion"),
            "isEncrypted": device.get("isEncrypted"),
        },
        "management": {
            "enrolledDateTime": device.get("enrolledDateTime"),
            "lastSyncDateTime": device.get("lastSyncDateTime"),
            "managementState": device.get("managementState"),
        },
        "compliance": {
            "complianceState": device.get("complianceState"),
            "policies": [{"name": p.get("displayName"), "state": p.get("state")} for p in compliance_states]
        }
    }


@mcp.tool()
async def search_devices(search_term: str, search_by: str = "deviceName") -> dict[str, Any]:
    """
    Search for devices by name, user, or serial number.
    
    Args:
        search_term: The value to search for
        search_by: Field to search - "deviceName", "userPrincipalName", "serialNumber"
    """
    client = get_graph_client()
    
    filter_query = f"contains({search_by}, '{search_term}')"
    endpoint = f"/deviceManagement/managedDevices?$filter={filter_query}&$top=50"
    
    response = await client.get(endpoint)
    devices = response.get("value", [])
    
    return {
        "search_term": search_term,
        "count": len(devices),
        "devices": [
            {
                "id": d.get("id"),
                "deviceName": d.get("deviceName"),
                "userPrincipalName": d.get("userPrincipalName"),
                "serialNumber": d.get("serialNumber"),
                "complianceState": d.get("complianceState"),
            }
            for d in devices
        ]
    }


@mcp.tool()
async def get_noncompliant_devices(top: int = 50) -> dict[str, Any]:
    """
    Get a list of non-compliant devices.
    
    Args:
        top: Maximum number of devices to return
    """
    client = get_graph_client()
    
    response = await client.get(
        f"/deviceManagement/managedDevices?$filter=complianceState eq 'noncompliant'&$top={top}"
    )
    devices = response.get("value", [])
    
    return {
        "count": len(devices),
        "noncompliant_devices": [
            {
                "id": d.get("id"),
                "deviceName": d.get("deviceName"),
                "userPrincipalName": d.get("userPrincipalName"),
                "operatingSystem": d.get("operatingSystem"),
                "lastSyncDateTime": d.get("lastSyncDateTime"),
            }
            for d in devices
        ]
    }


@mcp.tool()
async def sync_device(device_id: str) -> dict[str, Any]:
    """
    Trigger a sync for a managed device.
    
    Args:
        device_id: The Intune device ID
    """
    client = get_graph_client()
    
    device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
    device_name = device.get("deviceName", "Unknown")
    
    await client.post(f"/deviceManagement/managedDevices/{device_id}/syncDevice")
    
    return {
        "status": "success",
        "message": f"Sync command sent to device '{device_name}'",
        "device_id": device_id
    }


@mcp.tool()
async def restart_device(device_id: str) -> dict[str, Any]:
    """
    Restart a managed device remotely.
    
    Args:
        device_id: The Intune device ID
    """
    client = get_graph_client()
    
    device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
    device_name = device.get("deviceName", "Unknown")
    
    await client.post(f"/deviceManagement/managedDevices/{device_id}/rebootNow")
    
    return {
        "status": "success",
        "message": f"Restart command sent to device '{device_name}'"
    }


@mcp.tool()
async def remote_lock_device(device_id: str) -> dict[str, Any]:
    """
    Remotely lock a managed device.
    
    Args:
        device_id: The Intune device ID
    """
    client = get_graph_client()
    
    device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
    device_name = device.get("deviceName", "Unknown")
    
    await client.post(f"/deviceManagement/managedDevices/{device_id}/remoteLock")
    
    return {
        "status": "success",
        "message": f"Remote lock command sent to device '{device_name}'"
    }


@mcp.tool()
async def wipe_device(device_id: str, keep_enrollment_data: bool = False, confirm: bool = False) -> dict[str, Any]:
    """
    Wipe a managed device. THIS IS A DESTRUCTIVE ACTION - requires confirm=True.
    
    Args:
        device_id: The Intune device ID
        keep_enrollment_data: If True, keeps Intune enrollment data
        confirm: Must be True to execute the wipe
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "WARNING: WIPE is destructive! Set confirm=True to proceed."
        }
    
    client = get_graph_client()
    device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
    device_name = device.get("deviceName", "Unknown")
    
    await client.post(
        f"/deviceManagement/managedDevices/{device_id}/wipe",
        json={"keepEnrollmentData": keep_enrollment_data, "keepUserData": False}
    )
    
    return {
        "status": "success",
        "message": f"WIPE command sent to device '{device_name}'",
        "device_id": device_id
    }


@mcp.tool()
async def retire_device(device_id: str, confirm: bool = False) -> dict[str, Any]:
    """
    Retire a managed device (removes company data, keeps personal data). Requires confirm=True.
    
    Args:
        device_id: The Intune device ID
        confirm: Must be True to execute
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "WARNING: RETIRE will remove company data! Set confirm=True to proceed."
        }
    
    client = get_graph_client()
    device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
    device_name = device.get("deviceName", "Unknown")
    
    await client.post(f"/deviceManagement/managedDevices/{device_id}/retire")
    
    return {
        "status": "success",
        "message": f"Retire command sent to device '{device_name}'"
    }


# ============== APP MANAGEMENT TOOLS ==============

@mcp.tool()
async def list_mobile_apps(top: int = 50) -> dict[str, Any]:
    """
    List all mobile apps in Intune.
    
    Args:
        top: Maximum number of apps to return
    """
    client = get_graph_client()
    
    response = await client.get(f"/deviceAppManagement/mobileApps?$top={top}")
    apps = response.get("value", [])
    
    return {
        "count": len(apps),
        "apps": [
            {
                "id": app.get("id"),
                "displayName": app.get("displayName"),
                "publisher": app.get("publisher"),
                "appType": app.get("@odata.type", "").replace("#microsoft.graph.", ""),
            }
            for app in apps
        ]
    }


@mcp.tool()
async def get_app_details(app_id: str) -> dict[str, Any]:
    """
    Get detailed information about a specific app.
    
    Args:
        app_id: The Intune app ID
    """
    client = get_graph_client()
    
    app = await client.get(f"/deviceAppManagement/mobileApps/{app_id}")
    
    try:
        assignments = await client.get(f"/deviceAppManagement/mobileApps/{app_id}/assignments")
        assignment_list = assignments.get("value", [])
    except:
        assignment_list = []
    
    return {
        "app_info": {
            "id": app.get("id"),
            "displayName": app.get("displayName"),
            "description": app.get("description"),
            "publisher": app.get("publisher"),
            "appType": app.get("@odata.type", "").replace("#microsoft.graph.", ""),
        },
        "assignments": [
            {"id": a.get("id"), "intent": a.get("intent")}
            for a in assignment_list
        ]
    }


@mcp.tool()
async def search_apps(search_term: str) -> dict[str, Any]:
    """
    Search for apps by name.
    
    Args:
        search_term: The app name to search for
    """
    client = get_graph_client()
    
    response = await client.get(
        f"/deviceAppManagement/mobileApps?$filter=contains(displayName, '{search_term}')&$top=50"
    )
    apps = response.get("value", [])
    
    return {
        "search_term": search_term,
        "count": len(apps),
        "apps": [
            {
                "id": app.get("id"),
                "displayName": app.get("displayName"),
                "publisher": app.get("publisher"),
            }
            for app in apps
        ]
    }


# ============== POLICY MANAGEMENT TOOLS ==============

@mcp.tool()
async def list_compliance_policies() -> dict[str, Any]:
    """
    List all device compliance policies.
    """
    client = get_graph_client()
    
    response = await client.get("/deviceManagement/deviceCompliancePolicies")
    policies = response.get("value", [])
    
    return {
        "count": len(policies),
        "policies": [
            {
                "id": p.get("id"),
                "displayName": p.get("displayName"),
                "description": p.get("description"),
            }
            for p in policies
        ]
    }


@mcp.tool()
async def list_configuration_profiles() -> dict[str, Any]:
    """
    List all device configuration profiles.
    """
    client = get_graph_client()
    
    response = await client.get("/deviceManagement/deviceConfigurations")
    configs = response.get("value", [])
    
    return {
        "count": len(configs),
        "profiles": [
            {
                "id": c.get("id"),
                "displayName": c.get("displayName"),
                "description": c.get("description"),
            }
            for c in configs
        ]
    }


# ============== AUTOPILOT TOOLS ==============

@mcp.tool()
async def list_autopilot_devices(top: int = 50) -> dict[str, Any]:
    """
    List all Windows Autopilot devices.
    
    Args:
        top: Maximum number of devices to return
    """
    client = get_graph_client()
    
    response = await client.get(
        f"/deviceManagement/windowsAutopilotDeviceIdentities?$top={top}"
    )
    devices = response.get("value", [])
    
    return {
        "count": len(devices),
        "autopilot_devices": [
            {
                "id": d.get("id"),
                "serialNumber": d.get("serialNumber"),
                "model": d.get("model"),
                "groupTag": d.get("groupTag"),
                "enrollmentState": d.get("enrollmentState"),
            }
            for d in devices
        ]
    }


@mcp.tool()
async def list_autopilot_profiles() -> dict[str, Any]:
    """
    List all Windows Autopilot deployment profiles.
    """
    client = get_graph_client()
    
    response = await client.get("/deviceManagement/windowsAutopilotDeploymentProfiles")
    profiles = response.get("value", [])
    
    return {
        "count": len(profiles),
        "profiles": [
            {
                "id": p.get("id"),
                "displayName": p.get("displayName"),
                "description": p.get("description"),
            }
            for p in profiles
        ]
    }


# ============== USER/GROUP TOOLS ==============

@mcp.tool()
async def get_user(user_id: str) -> dict[str, Any]:
    """
    Get details of a user by ID or UPN.
    
    Args:
        user_id: The user ID or userPrincipalName
    """
    client = get_graph_client()
    
    user = await client.get(f"/users/{user_id}")
    
    return {
        "id": user.get("id"),
        "displayName": user.get("displayName"),
        "userPrincipalName": user.get("userPrincipalName"),
        "mail": user.get("mail"),
        "jobTitle": user.get("jobTitle"),
        "department": user.get("department"),
    }


@mcp.tool()
async def search_users(search_term: str) -> dict[str, Any]:
    """
    Search for users by name.
    
    Args:
        search_term: The name to search for
    """
    client = get_graph_client()
    
    response = await client.get(
        f"/users?$filter=startswith(displayName, '{search_term}')&$top=50"
    )
    users = response.get("value", [])
    
    return {
        "search_term": search_term,
        "count": len(users),
        "users": [
            {
                "id": u.get("id"),
                "displayName": u.get("displayName"),
                "userPrincipalName": u.get("userPrincipalName"),
            }
            for u in users
        ]
    }


@mcp.tool()
async def get_user_devices(user_id: str) -> dict[str, Any]:
    """
    Get all managed devices for a specific user.
    
    Args:
        user_id: The user ID or userPrincipalName
    """
    client = get_graph_client()
    
    user = await client.get(f"/users/{user_id}?$select=displayName,userPrincipalName")
    
    devices = await client.get(
        f"/deviceManagement/managedDevices?$filter=userPrincipalName eq '{user['userPrincipalName']}'"
    )
    device_list = devices.get("value", [])
    
    return {
        "user": user.get("displayName"),
        "device_count": len(device_list),
        "devices": [
            {
                "id": d.get("id"),
                "deviceName": d.get("deviceName"),
                "operatingSystem": d.get("operatingSystem"),
                "complianceState": d.get("complianceState"),
            }
            for d in device_list
        ]
    }


@mcp.tool()
async def list_groups(top: int = 50) -> dict[str, Any]:
    """
    List Azure AD groups.
    
    Args:
        top: Maximum number of groups to return
    """
    client = get_graph_client()
    
    response = await client.get(f"/groups?$top={top}")
    groups = response.get("value", [])
    
    return {
        "count": len(groups),
        "groups": [
            {
                "id": g.get("id"),
                "displayName": g.get("displayName"),
                "description": g.get("description"),
            }
            for g in groups
        ]
    }


@mcp.tool()
async def search_groups(search_term: str) -> dict[str, Any]:
    """
    Search for groups by name.
    
    Args:
        search_term: The group name to search for
    """
    client = get_graph_client()
    
    response = await client.get(
        f"/groups?$filter=startswith(displayName, '{search_term}')&$top=50"
    )
    groups = response.get("value", [])
    
    return {
        "search_term": search_term,
        "count": len(groups),
        "groups": [
            {
                "id": g.get("id"),
                "displayName": g.get("displayName"),
            }
            for g in groups
        ]
    }


# Entry point
if __name__ == "__main__":
    mcp.run()
