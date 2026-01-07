#!/usr/bin/env python3
"""
Microsoft Graph MCP Server for Intune & Entra ID Management

A comprehensive MCP server that provides tools for managing:
- Microsoft Intune (devices, apps, policies, scripts)
- Entra ID (users, groups, conditional access, authentication)
- Windows 365 Cloud PCs
- Tenant administration
- Security and compliance
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

# Import all tool modules
from intune_mcp_server.tools import entra_users
from intune_mcp_server.tools import entra_groups
from intune_mcp_server.tools import conditional_access
from intune_mcp_server.tools import authentication
from intune_mcp_server.tools import reports
from intune_mcp_server.tools import cloud_pc
from intune_mcp_server.tools import tenant_admin
from intune_mcp_server.tools import scripts
from intune_mcp_server.tools import security
from intune_mcp_server.tools import entra_devices

# Create the MCP server instance using FastMCP
mcp = FastMCP("intune-entra-mcp-server")


# ============== CORE TOOLS ==============

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
async def list_managed_devices(filter_query: str = "", top: int = 50) -> dict[str, Any]:
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
    """Trigger a sync for a managed device."""
    client = get_graph_client()
    device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
    device_name = device.get("deviceName", "Unknown")
    await client.post(f"/deviceManagement/managedDevices/{device_id}/syncDevice")
    return {"status": "success", "message": f"Sync command sent to device '{device_name}'", "device_id": device_id}


@mcp.tool()
async def restart_device(device_id: str) -> dict[str, Any]:
    """Restart a managed device remotely."""
    client = get_graph_client()
    device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
    device_name = device.get("deviceName", "Unknown")
    await client.post(f"/deviceManagement/managedDevices/{device_id}/rebootNow")
    return {"status": "success", "message": f"Restart command sent to device '{device_name}'"}


@mcp.tool()
async def remote_lock_device(device_id: str) -> dict[str, Any]:
    """Remotely lock a managed device."""
    client = get_graph_client()
    device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
    device_name = device.get("deviceName", "Unknown")
    await client.post(f"/deviceManagement/managedDevices/{device_id}/remoteLock")
    return {"status": "success", "message": f"Remote lock command sent to device '{device_name}'"}


@mcp.tool()
async def wipe_device(device_id: str, keep_enrollment_data: bool = False, confirm: bool = False) -> dict[str, Any]:
    """Wipe a managed device. THIS IS A DESTRUCTIVE ACTION - requires confirm=True."""
    if not confirm:
        return {"status": "confirmation_required", "message": "WARNING: WIPE is destructive! Set confirm=True to proceed."}
    client = get_graph_client()
    device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
    device_name = device.get("deviceName", "Unknown")
    await client.post(f"/deviceManagement/managedDevices/{device_id}/wipe", json={"keepEnrollmentData": keep_enrollment_data, "keepUserData": False})
    return {"status": "success", "message": f"WIPE command sent to device '{device_name}'", "device_id": device_id}


@mcp.tool()
async def retire_device(device_id: str, confirm: bool = False) -> dict[str, Any]:
    """Retire a managed device (removes company data, keeps personal data). Requires confirm=True."""
    if not confirm:
        return {"status": "confirmation_required", "message": "WARNING: RETIRE will remove company data! Set confirm=True to proceed."}
    client = get_graph_client()
    device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
    device_name = device.get("deviceName", "Unknown")
    await client.post(f"/deviceManagement/managedDevices/{device_id}/retire")
    return {"status": "success", "message": f"Retire command sent to device '{device_name}'"}


# ============== APP MANAGEMENT TOOLS ==============

@mcp.tool()
async def list_mobile_apps(top: int = 50) -> dict[str, Any]:
    """List all mobile apps in Intune."""
    client = get_graph_client()
    response = await client.get(f"/deviceAppManagement/mobileApps?$top={top}")
    apps = response.get("value", [])
    return {
        "count": len(apps),
        "apps": [{"id": app.get("id"), "displayName": app.get("displayName"), "publisher": app.get("publisher"), "appType": app.get("@odata.type", "").replace("#microsoft.graph.", "")} for app in apps]
    }


@mcp.tool()
async def get_app_details(app_id: str) -> dict[str, Any]:
    """Get detailed information about a specific app."""
    client = get_graph_client()
    app = await client.get(f"/deviceAppManagement/mobileApps/{app_id}")
    try:
        assignments = await client.get(f"/deviceAppManagement/mobileApps/{app_id}/assignments")
        assignment_list = assignments.get("value", [])
    except:
        assignment_list = []
    return {"app_info": {"id": app.get("id"), "displayName": app.get("displayName"), "description": app.get("description"), "publisher": app.get("publisher"), "appType": app.get("@odata.type", "").replace("#microsoft.graph.", "")}, "assignments": [{"id": a.get("id"), "intent": a.get("intent")} for a in assignment_list]}


@mcp.tool()
async def search_apps(search_term: str) -> dict[str, Any]:
    """Search for apps by name."""
    client = get_graph_client()
    response = await client.get(f"/deviceAppManagement/mobileApps?$filter=contains(displayName, '{search_term}')&$top=50")
    apps = response.get("value", [])
    return {"search_term": search_term, "count": len(apps), "apps": [{"id": app.get("id"), "displayName": app.get("displayName"), "publisher": app.get("publisher")} for app in apps]}


# ============== POLICY MANAGEMENT TOOLS ==============

@mcp.tool()
async def list_compliance_policies() -> dict[str, Any]:
    """List all device compliance policies."""
    client = get_graph_client()
    response = await client.get("/deviceManagement/deviceCompliancePolicies")
    policies = response.get("value", [])
    return {"count": len(policies), "policies": [{"id": p.get("id"), "displayName": p.get("displayName"), "description": p.get("description")} for p in policies]}


@mcp.tool()
async def list_configuration_profiles() -> dict[str, Any]:
    """List all device configuration profiles."""
    client = get_graph_client()
    response = await client.get("/deviceManagement/deviceConfigurations")
    configs = response.get("value", [])
    return {"count": len(configs), "profiles": [{"id": c.get("id"), "displayName": c.get("displayName"), "description": c.get("description")} for c in configs]}


# ============== AUTOPILOT TOOLS ==============

@mcp.tool()
async def list_autopilot_devices(top: int = 50) -> dict[str, Any]:
    """List all Windows Autopilot devices."""
    client = get_graph_client()
    response = await client.get(f"/deviceManagement/windowsAutopilotDeviceIdentities?$top={top}")
    devices = response.get("value", [])
    return {"count": len(devices), "autopilot_devices": [{"id": d.get("id"), "serialNumber": d.get("serialNumber"), "model": d.get("model"), "groupTag": d.get("groupTag"), "enrollmentState": d.get("enrollmentState")} for d in devices]}


@mcp.tool()
async def list_autopilot_profiles() -> dict[str, Any]:
    """List all Windows Autopilot deployment profiles."""
    client = get_graph_client()
    response = await client.get("/deviceManagement/windowsAutopilotDeploymentProfiles")
    profiles = response.get("value", [])
    return {"count": len(profiles), "profiles": [{"id": p.get("id"), "displayName": p.get("displayName"), "description": p.get("description")} for p in profiles]}


# ============== ENTRA ID USER TOOLS ==============

@mcp.tool()
async def list_users(top: int = 50, filter_query: str = "") -> dict[str, Any]:
    """List all users in the tenant."""
    return await entra_users.list_users(top, filter_query)

@mcp.tool()
async def get_user(user_id: str) -> dict[str, Any]:
    """Get details of a user by ID or UPN."""
    return await entra_users.get_user_details(user_id)

@mcp.tool()
async def create_user(display_name: str, user_principal_name: str, mail_nickname: str, password: str, account_enabled: bool = True, force_change_password: bool = True, given_name: str = "", surname: str = "", job_title: str = "", department: str = "") -> dict[str, Any]:
    """Create a new user in Entra ID."""
    return await entra_users.create_user(display_name, user_principal_name, mail_nickname, password, account_enabled, force_change_password, given_name, surname, job_title, department)

@mcp.tool()
async def update_user(user_id: str, display_name: str = None, given_name: str = None, surname: str = None, job_title: str = None, department: str = None, office_location: str = None, mobile_phone: str = None) -> dict[str, Any]:
    """Update user properties."""
    return await entra_users.update_user(user_id, display_name, given_name, surname, job_title, department, office_location, mobile_phone)

@mcp.tool()
async def delete_user(user_id: str, confirm: bool = False) -> dict[str, Any]:
    """Delete a user from Entra ID."""
    return await entra_users.delete_user(user_id, confirm)

@mcp.tool()
async def enable_user(user_id: str) -> dict[str, Any]:
    """Enable a user account."""
    return await entra_users.enable_user(user_id)

@mcp.tool()
async def disable_user(user_id: str) -> dict[str, Any]:
    """Disable a user account (blocks sign-in)."""
    return await entra_users.disable_user(user_id)

@mcp.tool()
async def reset_user_password(user_id: str, new_password: str, force_change_on_next_login: bool = True) -> dict[str, Any]:
    """Reset a user's password."""
    return await entra_users.reset_user_password(user_id, new_password, force_change_on_next_login)

@mcp.tool()
async def revoke_user_sessions(user_id: str) -> dict[str, Any]:
    """Revoke all refresh tokens for a user (forces re-authentication)."""
    return await entra_users.revoke_user_sessions(user_id)

@mcp.tool()
async def search_users(search_term: str) -> dict[str, Any]:
    """Search for users by name."""
    client = get_graph_client()
    response = await client.get(f"/users?$filter=startswith(displayName, '{search_term}')&$top=50")
    users = response.get("value", [])
    return {"search_term": search_term, "count": len(users), "users": [{"id": u.get("id"), "displayName": u.get("displayName"), "userPrincipalName": u.get("userPrincipalName")} for u in users]}

@mcp.tool()
async def get_user_devices(user_id: str) -> dict[str, Any]:
    """Get all managed devices for a specific user."""
    client = get_graph_client()
    user = await client.get(f"/users/{user_id}?$select=displayName,userPrincipalName")
    devices = await client.get(f"/deviceManagement/managedDevices?$filter=userPrincipalName eq '{user['userPrincipalName']}'")
    device_list = devices.get("value", [])
    return {"user": user.get("displayName"), "device_count": len(device_list), "devices": [{"id": d.get("id"), "deviceName": d.get("deviceName"), "operatingSystem": d.get("operatingSystem"), "complianceState": d.get("complianceState")} for d in device_list]}

@mcp.tool()
async def get_user_licenses(user_id: str) -> dict[str, Any]:
    """Get license assignments for a user."""
    return await entra_users.get_user_licenses(user_id)

@mcp.tool()
async def assign_license(user_id: str, sku_id: str) -> dict[str, Any]:
    """Assign a license to a user."""
    return await entra_users.assign_license(user_id, sku_id)

@mcp.tool()
async def remove_license(user_id: str, sku_id: str) -> dict[str, Any]:
    """Remove a license from a user."""
    return await entra_users.remove_license(user_id, sku_id)

@mcp.tool()
async def list_available_licenses() -> dict[str, Any]:
    """List all available licenses (SKUs) in the tenant."""
    return await entra_users.list_available_licenses()

@mcp.tool()
async def get_deleted_users(top: int = 50) -> dict[str, Any]:
    """List deleted users (recoverable within 30 days)."""
    return await entra_users.get_deleted_users(top)

@mcp.tool()
async def restore_deleted_user(user_id: str) -> dict[str, Any]:
    """Restore a deleted user."""
    return await entra_users.restore_deleted_user(user_id)


# ============== ENTRA ID GROUP TOOLS ==============

@mcp.tool()
async def list_groups(top: int = 50) -> dict[str, Any]:
    """List Azure AD groups."""
    client = get_graph_client()
    response = await client.get(f"/groups?$top={top}")
    groups = response.get("value", [])
    return {"count": len(groups), "groups": [{"id": g.get("id"), "displayName": g.get("displayName"), "description": g.get("description")} for g in groups]}

@mcp.tool()
async def search_groups(search_term: str) -> dict[str, Any]:
    """Search for groups by name."""
    client = get_graph_client()
    response = await client.get(f"/groups?$filter=startswith(displayName, '{search_term}')&$top=50")
    groups = response.get("value", [])
    return {"search_term": search_term, "count": len(groups), "groups": [{"id": g.get("id"), "displayName": g.get("displayName")} for g in groups]}

@mcp.tool()
async def get_group(group_id: str) -> dict[str, Any]:
    """Get details of a specific group."""
    return await entra_groups.get_group_details(group_id)

@mcp.tool()
async def create_security_group(display_name: str, description: str = "") -> dict[str, Any]:
    """Create a new security group."""
    return await entra_groups.create_security_group(display_name, description)

@mcp.tool()
async def create_microsoft365_group(display_name: str, description: str = "", visibility: str = "Private") -> dict[str, Any]:
    """Create a new Microsoft 365 group."""
    return await entra_groups.create_microsoft365_group(display_name, description, visibility=visibility)

@mcp.tool()
async def create_dynamic_security_group(display_name: str, membership_rule: str, description: str = "") -> dict[str, Any]:
    """Create a dynamic security group with automatic membership based on a rule."""
    return await entra_groups.create_dynamic_security_group(display_name, membership_rule, description)

@mcp.tool()
async def delete_group(group_id: str, confirm: bool = False) -> dict[str, Any]:
    """Delete a group."""
    return await entra_groups.delete_group(group_id, confirm)

@mcp.tool()
async def get_group_members(group_id: str, top: int = 100) -> dict[str, Any]:
    """Get all members of a group."""
    return await entra_groups.get_group_members(group_id, top)

@mcp.tool()
async def add_group_member(group_id: str, member_id: str) -> dict[str, Any]:
    """Add a member to a group."""
    return await entra_groups.add_group_member(group_id, member_id)

@mcp.tool()
async def remove_group_member(group_id: str, member_id: str) -> dict[str, Any]:
    """Remove a member from a group."""
    return await entra_groups.remove_group_member(group_id, member_id)

@mcp.tool()
async def get_group_owners(group_id: str) -> dict[str, Any]:
    """Get owners of a group."""
    return await entra_groups.get_group_owners(group_id)

@mcp.tool()
async def add_group_owner(group_id: str, owner_id: str) -> dict[str, Any]:
    """Add an owner to a group."""
    return await entra_groups.add_group_owner(group_id, owner_id)


# ============== CONDITIONAL ACCESS TOOLS ==============

@mcp.tool()
async def list_conditional_access_policies() -> dict[str, Any]:
    """List all Conditional Access policies."""
    return await conditional_access.list_conditional_access_policies()

@mcp.tool()
async def get_conditional_access_policy(policy_id: str) -> dict[str, Any]:
    """Get detailed information about a specific Conditional Access policy."""
    return await conditional_access.get_conditional_access_policy(policy_id)

@mcp.tool()
async def enable_conditional_access_policy(policy_id: str) -> dict[str, Any]:
    """Enable a Conditional Access policy."""
    return await conditional_access.enable_conditional_access_policy(policy_id)

@mcp.tool()
async def disable_conditional_access_policy(policy_id: str) -> dict[str, Any]:
    """Disable a Conditional Access policy."""
    return await conditional_access.disable_conditional_access_policy(policy_id)

@mcp.tool()
async def list_named_locations() -> dict[str, Any]:
    """List all named locations used in Conditional Access."""
    return await conditional_access.list_named_locations()


# ============== AUTHENTICATION TOOLS ==============

@mcp.tool()
async def get_user_authentication_methods(user_id: str) -> dict[str, Any]:
    """Get all authentication methods registered for a user."""
    return await authentication.get_user_authentication_methods(user_id)

@mcp.tool()
async def get_user_mfa_status(user_id: str) -> dict[str, Any]:
    """Get MFA status and registered methods for a user."""
    return await authentication.get_user_mfa_status(user_id)

@mcp.tool()
async def get_sign_in_logs(top: int = 50, user_id: str = None, status: str = None, days_back: int = 7) -> dict[str, Any]:
    """Get sign-in logs with optional filtering."""
    return await authentication.get_sign_in_logs(top, user_id, status=status, days_back=days_back)

@mcp.tool()
async def get_risky_users(top: int = 50, risk_level: str = None) -> dict[str, Any]:
    """Get users flagged as risky by Identity Protection."""
    return await authentication.get_risky_users(top, risk_level)

@mcp.tool()
async def get_risk_detections(top: int = 50, days_back: int = 7) -> dict[str, Any]:
    """Get risk detections from Identity Protection."""
    return await authentication.get_risk_detections(top, days_back)

@mcp.tool()
async def dismiss_risky_user(user_id: str) -> dict[str, Any]:
    """Dismiss the risk for a user (mark as false positive)."""
    return await authentication.dismiss_risky_user(user_id)

@mcp.tool()
async def get_directory_audit_logs(top: int = 50, category: str = None, days_back: int = 7) -> dict[str, Any]:
    """Get directory audit logs."""
    return await authentication.get_directory_audit_logs(top, category, days_back=days_back)


# ============== REPORTS TOOLS ==============

@mcp.tool()
async def get_device_compliance_report() -> dict[str, Any]:
    """Get overall device compliance summary across all managed devices."""
    return await reports.get_device_compliance_report()

@mcp.tool()
async def get_device_configuration_status(profile_id: str) -> dict[str, Any]:
    """Get deployment status for a specific configuration profile."""
    return await reports.get_device_configuration_status(profile_id)

@mcp.tool()
async def get_compliance_policy_status(policy_id: str) -> dict[str, Any]:
    """Get deployment status for a specific compliance policy."""
    return await reports.get_compliance_policy_status(policy_id)

@mcp.tool()
async def get_app_installation_status(app_id: str) -> dict[str, Any]:
    """Get installation status for a specific app."""
    return await reports.get_app_installation_status(app_id)

@mcp.tool()
async def get_license_usage_report() -> dict[str, Any]:
    """Get license usage summary across the tenant."""
    return await reports.get_license_usage_report()

@mcp.tool()
async def get_hardware_inventory_report() -> dict[str, Any]:
    """Get hardware inventory summary for all managed devices."""
    return await reports.get_hardware_inventory_report()


# ============== CLOUD PC TOOLS ==============

@mcp.tool()
async def list_cloud_pcs(top: int = 50) -> dict[str, Any]:
    """List all Cloud PCs in the tenant."""
    return await cloud_pc.list_cloud_pcs(top)

@mcp.tool()
async def get_cloud_pc_details(cloud_pc_id: str) -> dict[str, Any]:
    """Get detailed information about a specific Cloud PC."""
    return await cloud_pc.get_cloud_pc_details(cloud_pc_id)

@mcp.tool()
async def restart_cloud_pc(cloud_pc_id: str) -> dict[str, Any]:
    """Restart a Cloud PC."""
    return await cloud_pc.restart_cloud_pc(cloud_pc_id)

@mcp.tool()
async def reprovision_cloud_pc(cloud_pc_id: str, confirm: bool = False) -> dict[str, Any]:
    """Reprovision a Cloud PC. This will reset it to its original state."""
    return await cloud_pc.reprovision_cloud_pc(cloud_pc_id, confirm)

@mcp.tool()
async def list_provisioning_policies() -> dict[str, Any]:
    """List all Cloud PC provisioning policies."""
    return await cloud_pc.list_provisioning_policies()

@mcp.tool()
async def list_gallery_images() -> dict[str, Any]:
    """List available gallery images for Cloud PC provisioning."""
    return await cloud_pc.list_gallery_images()

@mcp.tool()
async def get_cloud_pc_overview() -> dict[str, Any]:
    """Get an overview of all Cloud PCs in the tenant."""
    return await cloud_pc.get_cloud_pc_overview()


# ============== TENANT ADMIN TOOLS ==============

@mcp.tool()
async def get_organization_info() -> dict[str, Any]:
    """Get organization/tenant information."""
    return await tenant_admin.get_organization_info()

@mcp.tool()
async def get_tenant_domains() -> dict[str, Any]:
    """Get all domains associated with the tenant."""
    return await tenant_admin.get_tenant_domains()

@mcp.tool()
async def get_service_health() -> dict[str, Any]:
    """Get Microsoft 365 service health status."""
    return await tenant_admin.get_service_health()

@mcp.tool()
async def get_service_issues(service_name: str = None, top: int = 50) -> dict[str, Any]:
    """Get current and recent service issues."""
    return await tenant_admin.get_service_issues(service_name, top)

@mcp.tool()
async def list_directory_roles() -> dict[str, Any]:
    """List all active directory roles."""
    return await tenant_admin.list_directory_roles()

@mcp.tool()
async def get_directory_role_members(role_id: str) -> dict[str, Any]:
    """Get members of a specific directory role."""
    return await tenant_admin.get_directory_role_members(role_id)

@mcp.tool()
async def get_global_admins() -> dict[str, Any]:
    """Get all Global Administrator role members."""
    return await tenant_admin.get_global_admins()

@mcp.tool()
async def get_subscriptions() -> dict[str, Any]:
    """Get all subscribed SKUs (licenses) for the tenant."""
    return await tenant_admin.get_subscriptions()

@mcp.tool()
async def list_app_registrations(top: int = 50) -> dict[str, Any]:
    """List all app registrations in the tenant."""
    return await tenant_admin.list_app_registrations(top)

@mcp.tool()
async def get_security_defaults_status() -> dict[str, Any]:
    """Get the status of security defaults for the tenant."""
    return await tenant_admin.get_security_defaults_status()


# ============== SCRIPTS TOOLS ==============

@mcp.tool()
async def list_device_management_scripts(top: int = 50) -> dict[str, Any]:
    """List all PowerShell scripts deployed through Intune."""
    return await scripts.list_device_management_scripts(top)

@mcp.tool()
async def get_device_management_script(script_id: str) -> dict[str, Any]:
    """Get details of a specific PowerShell script including the script content."""
    return await scripts.get_device_management_script(script_id)

@mcp.tool()
async def get_script_device_status(script_id: str, top: int = 100) -> dict[str, Any]:
    """Get the deployment status of a script across devices."""
    return await scripts.get_script_device_status(script_id, top)

@mcp.tool()
async def list_device_health_scripts(top: int = 50) -> dict[str, Any]:
    """List all proactive remediation scripts (device health scripts)."""
    return await scripts.list_device_health_scripts(top)

@mcp.tool()
async def get_device_health_script(script_id: str) -> dict[str, Any]:
    """Get details of a proactive remediation script."""
    return await scripts.get_device_health_script(script_id)

@mcp.tool()
async def get_device_health_script_status(script_id: str) -> dict[str, Any]:
    """Get the status summary for a proactive remediation script."""
    return await scripts.get_device_health_script_status(script_id)


# ============== SECURITY TOOLS ==============

@mcp.tool()
async def list_security_baselines() -> dict[str, Any]:
    """List all security baseline templates available."""
    return await security.list_security_baselines()

@mcp.tool()
async def list_security_baseline_profiles() -> dict[str, Any]:
    """List all deployed security baseline profiles."""
    return await security.list_security_baseline_profiles()

@mcp.tool()
async def get_security_baseline_status(intent_id: str) -> dict[str, Any]:
    """Get deployment status for a security baseline profile."""
    return await security.get_security_baseline_status(intent_id)

@mcp.tool()
async def list_app_protection_policies() -> dict[str, Any]:
    """List mobile app protection policies (MAM)."""
    return await security.list_app_protection_policies()

@mcp.tool()
async def list_enrollment_restrictions() -> dict[str, Any]:
    """List device enrollment restrictions."""
    return await security.list_enrollment_restrictions()

@mcp.tool()
async def list_device_categories() -> dict[str, Any]:
    """List all device categories."""
    return await security.list_device_categories()

@mcp.tool()
async def create_device_category(display_name: str, description: str = "") -> dict[str, Any]:
    """Create a new device category."""
    return await security.create_device_category(display_name, description)


# ============== ENTRA ID DEVICE TOOLS ==============

@mcp.tool()
async def list_entra_devices(top: int = 50, filter_query: str = "") -> dict[str, Any]:
    """List all devices registered in Entra ID (Azure AD)."""
    return await entra_devices.list_entra_devices(top, filter_query)

@mcp.tool()
async def search_entra_devices(search_term: str) -> dict[str, Any]:
    """Search for devices in Entra ID by display name."""
    return await entra_devices.search_entra_devices(search_term)

@mcp.tool()
async def get_entra_device(device_id: str) -> dict[str, Any]:
    """Get details of a specific Entra ID device."""
    return await entra_devices.get_entra_device(device_id)

@mcp.tool()
async def delete_entra_device(device_name: str = None, device_id: str = None, confirm: bool = False) -> dict[str, Any]:
    """Delete a device from Entra ID (Azure AD). Requires confirm=True."""
    return await entra_devices.delete_entra_device(device_name, device_id, confirm)

@mcp.tool()
async def delete_intune_device(device_name: str = None, device_id: str = None, confirm: bool = False) -> dict[str, Any]:
    """Delete a device from Intune (not just retire, but fully delete). Requires confirm=True."""
    return await entra_devices.delete_intune_device(device_name, device_id, confirm)

@mcp.tool()
async def delete_device_from_all(device_name: str, confirm: bool = False) -> dict[str, Any]:
    """Delete a device from both Intune AND Entra ID. Requires confirm=True."""
    return await entra_devices.delete_device_from_all(device_name, confirm)

@mcp.tool()
async def disable_entra_device(device_id: str) -> dict[str, Any]:
    """Disable a device in Entra ID."""
    return await entra_devices.disable_entra_device(device_id)

@mcp.tool()
async def enable_entra_device(device_id: str) -> dict[str, Any]:
    """Enable a device in Entra ID."""
    return await entra_devices.enable_entra_device(device_id)


# Entry point
if __name__ == "__main__":
    mcp.run()
