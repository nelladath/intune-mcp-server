"""Device Management Tools for Intune MCP Server."""

from typing import Any
from mcp.server import Server

from ..graph_client import get_graph_client


def register_device_tools(server: Server):
    """Register all device management tools with the MCP server."""
    
    @server.tool()
    async def list_managed_devices(
        filter_query: str = "",
        top: int = 50,
        select_fields: str = ""
    ) -> dict[str, Any]:
        """
        List all Intune managed devices.
        
        Args:
            filter_query: OData filter (e.g., "operatingSystem eq 'Windows'")
            top: Maximum number of devices to return (default 50, max 1000)
            select_fields: Comma-separated fields to return (e.g., "deviceName,serialNumber")
        
        Returns:
            List of managed devices with their details
        """
        client = get_graph_client()
        
        endpoint = "/deviceManagement/managedDevices"
        params = []
        
        if top:
            params.append(f"$top={min(top, 1000)}")
        if filter_query:
            params.append(f"$filter={filter_query}")
        if select_fields:
            params.append(f"$select={select_fields}")
        
        if params:
            endpoint += "?" + "&".join(params)
        
        response = await client.get(endpoint)
        devices = response.get("value", [])
        
        # Format response for readability
        formatted_devices = []
        for device in devices:
            formatted_devices.append({
                "id": device.get("id"),
                "deviceName": device.get("deviceName"),
                "userPrincipalName": device.get("userPrincipalName"),
                "operatingSystem": device.get("operatingSystem"),
                "osVersion": device.get("osVersion"),
                "complianceState": device.get("complianceState"),
                "managementState": device.get("managementState"),
                "lastSyncDateTime": device.get("lastSyncDateTime"),
                "serialNumber": device.get("serialNumber"),
                "model": device.get("model"),
                "manufacturer": device.get("manufacturer"),
            })
        
        return {
            "count": len(formatted_devices),
            "devices": formatted_devices
        }
    
    @server.tool()
    async def get_device_details(device_id: str) -> dict[str, Any]:
        """
        Get comprehensive details for a specific managed device.
        
        Args:
            device_id: The Intune device ID
        
        Returns:
            Complete device information including hardware, compliance, and configuration
        """
        client = get_graph_client()
        
        # Get basic device info
        device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
        
        # Get compliance policy states
        try:
            compliance = await client.get(
                f"/deviceManagement/managedDevices/{device_id}/deviceCompliancePolicyStates"
            )
            compliance_states = compliance.get("value", [])
        except Exception:
            compliance_states = []
        
        # Get configuration states
        try:
            config_states = await client.get(
                f"/deviceManagement/managedDevices/{device_id}/deviceConfigurationStates"
            )
            configuration_states = config_states.get("value", [])
        except Exception:
            configuration_states = []
        
        # Get detected apps
        try:
            apps = await client.get(
                f"/deviceManagement/managedDevices/{device_id}/detectedApps"
            )
            detected_apps = apps.get("value", [])
        except Exception:
            detected_apps = []
        
        return {
            "basic_info": {
                "id": device.get("id"),
                "deviceName": device.get("deviceName"),
                "userDisplayName": device.get("userDisplayName"),
                "userPrincipalName": device.get("userPrincipalName"),
                "emailAddress": device.get("emailAddress"),
                "managedDeviceOwnerType": device.get("managedDeviceOwnerType"),
            },
            "hardware": {
                "serialNumber": device.get("serialNumber"),
                "model": device.get("model"),
                "manufacturer": device.get("manufacturer"),
                "imei": device.get("imei"),
                "meid": device.get("meid"),
                "wiFiMacAddress": device.get("wiFiMacAddress"),
                "ethernetMacAddress": device.get("ethernetMacAddress"),
                "totalStorageSpaceInBytes": device.get("totalStorageSpaceInBytes"),
                "freeStorageSpaceInBytes": device.get("freeStorageSpaceInBytes"),
                "physicalMemoryInBytes": device.get("physicalMemoryInBytes"),
            },
            "os_info": {
                "operatingSystem": device.get("operatingSystem"),
                "osVersion": device.get("osVersion"),
                "deviceType": device.get("deviceType"),
                "exchangeAccessState": device.get("exchangeAccessState"),
            },
            "management": {
                "enrolledDateTime": device.get("enrolledDateTime"),
                "lastSyncDateTime": device.get("lastSyncDateTime"),
                "managementAgent": device.get("managementAgent"),
                "managementState": device.get("managementState"),
                "deviceEnrollmentType": device.get("deviceEnrollmentType"),
                "deviceRegistrationState": device.get("deviceRegistrationState"),
                "isEncrypted": device.get("isEncrypted"),
                "isSupervised": device.get("isSupervised"),
                "jailBroken": device.get("jailBroken"),
            },
            "compliance": {
                "complianceState": device.get("complianceState"),
                "complianceGracePeriodExpirationDateTime": device.get("complianceGracePeriodExpirationDateTime"),
                "policies": [
                    {
                        "displayName": p.get("displayName"),
                        "state": p.get("state"),
                        "settingCount": p.get("settingCount"),
                    }
                    for p in compliance_states
                ]
            },
            "configuration_states": [
                {
                    "displayName": c.get("displayName"),
                    "state": c.get("state"),
                }
                for c in configuration_states[:10]  # Limit to first 10
            ],
            "detected_apps_count": len(detected_apps),
            "azure_ad": {
                "azureADDeviceId": device.get("azureADDeviceId"),
                "azureADRegistered": device.get("azureADRegistered"),
            }
        }
    
    @server.tool()
    async def search_devices(
        search_term: str,
        search_by: str = "deviceName"
    ) -> dict[str, Any]:
        """
        Search for devices by name, user, or serial number.
        
        Args:
            search_term: The value to search for
            search_by: Field to search - "deviceName", "userPrincipalName", "serialNumber"
        
        Returns:
            List of matching devices
        """
        client = get_graph_client()
        
        # Build filter based on search field
        valid_fields = ["deviceName", "userPrincipalName", "serialNumber", "userDisplayName"]
        if search_by not in valid_fields:
            return {"error": f"Invalid search field. Use one of: {valid_fields}"}
        
        # Use contains for flexible matching
        filter_query = f"contains({search_by}, '{search_term}')"
        endpoint = f"/deviceManagement/managedDevices?$filter={filter_query}&$top=50"
        
        response = await client.get(endpoint)
        devices = response.get("value", [])
        
        return {
            "search_term": search_term,
            "search_field": search_by,
            "count": len(devices),
            "devices": [
                {
                    "id": d.get("id"),
                    "deviceName": d.get("deviceName"),
                    "userPrincipalName": d.get("userPrincipalName"),
                    "serialNumber": d.get("serialNumber"),
                    "operatingSystem": d.get("operatingSystem"),
                    "complianceState": d.get("complianceState"),
                    "lastSyncDateTime": d.get("lastSyncDateTime"),
                }
                for d in devices
            ]
        }
    
    @server.tool()
    async def sync_device(device_id: str) -> dict[str, Any]:
        """
        Trigger a sync for a managed device.
        
        Args:
            device_id: The Intune device ID
        
        Returns:
            Status of the sync request
        """
        client = get_graph_client()
        
        # First get device info for confirmation
        device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
        device_name = device.get("deviceName", "Unknown")
        
        # Trigger sync
        await client.post(f"/deviceManagement/managedDevices/{device_id}/syncDevice")
        
        return {
            "status": "success",
            "message": f"Sync command sent to device '{device_name}'",
            "device_id": device_id,
            "device_name": device_name,
            "note": "The device will sync on its next check-in"
        }
    
    @server.tool()
    async def restart_device(device_id: str) -> dict[str, Any]:
        """
        Restart a managed device remotely.
        
        Args:
            device_id: The Intune device ID
        
        Returns:
            Status of the restart request
        """
        client = get_graph_client()
        
        device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
        device_name = device.get("deviceName", "Unknown")
        
        await client.post(f"/deviceManagement/managedDevices/{device_id}/rebootNow")
        
        return {
            "status": "success",
            "message": f"Restart command sent to device '{device_name}'",
            "device_id": device_id,
            "device_name": device_name
        }
    
    @server.tool()
    async def remote_lock_device(device_id: str) -> dict[str, Any]:
        """
        Remotely lock a managed device.
        
        Args:
            device_id: The Intune device ID
        
        Returns:
            Status of the lock request
        """
        client = get_graph_client()
        
        device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
        device_name = device.get("deviceName", "Unknown")
        
        await client.post(f"/deviceManagement/managedDevices/{device_id}/remoteLock")
        
        return {
            "status": "success",
            "message": f"Remote lock command sent to device '{device_name}'",
            "device_id": device_id,
            "device_name": device_name
        }
    
    @server.tool()
    async def wipe_device(
        device_id: str,
        keep_enrollment_data: bool = False,
        keep_user_data: bool = False,
        confirm: bool = False
    ) -> dict[str, Any]:
        """
        Wipe a managed device. THIS IS A DESTRUCTIVE ACTION.
        
        Args:
            device_id: The Intune device ID
            keep_enrollment_data: If True, keeps Intune enrollment data
            keep_user_data: If True, keeps user data (only for certain device types)
            confirm: Must be True to execute the wipe
        
        Returns:
            Status of the wipe request
        """
        if not confirm:
            return {
                "status": "confirmation_required",
                "message": "⚠️ WIPE is a destructive action! Set confirm=True to proceed.",
                "warning": "This will erase all data on the device!"
            }
        
        client = get_graph_client()
        
        device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
        device_name = device.get("deviceName", "Unknown")
        user = device.get("userPrincipalName", "Unknown")
        
        await client.post(
            f"/deviceManagement/managedDevices/{device_id}/wipe",
            json={
                "keepEnrollmentData": keep_enrollment_data,
                "keepUserData": keep_user_data
            }
        )
        
        return {
            "status": "success",
            "message": f"⚠️ Wipe command sent to device '{device_name}'",
            "device_id": device_id,
            "device_name": device_name,
            "user": user,
            "keep_enrollment_data": keep_enrollment_data,
            "keep_user_data": keep_user_data
        }
    
    @server.tool()
    async def retire_device(device_id: str, confirm: bool = False) -> dict[str, Any]:
        """
        Retire a managed device (removes company data but keeps personal data).
        
        Args:
            device_id: The Intune device ID
            confirm: Must be True to execute the retire
        
        Returns:
            Status of the retire request
        """
        if not confirm:
            return {
                "status": "confirmation_required",
                "message": "⚠️ RETIRE will remove company data! Set confirm=True to proceed.",
                "note": "Personal data will be preserved"
            }
        
        client = get_graph_client()
        
        device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
        device_name = device.get("deviceName", "Unknown")
        
        await client.post(f"/deviceManagement/managedDevices/{device_id}/retire")
        
        return {
            "status": "success",
            "message": f"Retire command sent to device '{device_name}'",
            "device_id": device_id,
            "device_name": device_name,
            "note": "Company data will be removed, personal data preserved"
        }
    
    @server.tool()
    async def reset_device_passcode(device_id: str) -> dict[str, Any]:
        """
        Reset the passcode for a managed device.
        
        Args:
            device_id: The Intune device ID
        
        Returns:
            Status of the passcode reset request
        """
        client = get_graph_client()
        
        device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
        device_name = device.get("deviceName", "Unknown")
        
        await client.post(f"/deviceManagement/managedDevices/{device_id}/resetPasscode")
        
        return {
            "status": "success",
            "message": f"Passcode reset command sent to device '{device_name}'",
            "device_id": device_id,
            "device_name": device_name
        }
    
    @server.tool()
    async def get_device_compliance_summary() -> dict[str, Any]:
        """
        Get a summary of device compliance across all managed devices.
        
        Returns:
            Compliance summary with counts by state
        """
        client = get_graph_client()
        
        # Get all devices (paginated)
        all_devices = []
        endpoint = "/deviceManagement/managedDevices?$select=complianceState,operatingSystem&$top=999"
        
        response = await client.get(endpoint)
        all_devices.extend(response.get("value", []))
        
        # Count by compliance state
        compliance_counts = {}
        os_counts = {}
        
        for device in all_devices:
            state = device.get("complianceState", "unknown")
            os = device.get("operatingSystem", "unknown")
            
            compliance_counts[state] = compliance_counts.get(state, 0) + 1
            os_counts[os] = os_counts.get(os, 0) + 1
        
        return {
            "total_devices": len(all_devices),
            "compliance_summary": compliance_counts,
            "os_distribution": os_counts
        }
    
    @server.tool()
    async def get_noncompliant_devices(top: int = 50) -> dict[str, Any]:
        """
        Get a list of non-compliant devices.
        
        Args:
            top: Maximum number of devices to return
        
        Returns:
            List of non-compliant devices with details
        """
        client = get_graph_client()
        
        endpoint = f"/deviceManagement/managedDevices?$filter=complianceState eq 'noncompliant'&$top={top}"
        
        response = await client.get(endpoint)
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
                    "complianceGracePeriodExpirationDateTime": d.get("complianceGracePeriodExpirationDateTime"),
                }
                for d in devices
            ]
        }
    
    @server.tool()
    async def get_stale_devices(days_inactive: int = 30, top: int = 50) -> dict[str, Any]:
        """
        Get devices that haven't synced in a specified number of days.
        
        Args:
            days_inactive: Number of days since last sync (default 30)
            top: Maximum number of devices to return
        
        Returns:
            List of stale devices
        """
        client = get_graph_client()
        
        from datetime import datetime, timedelta
        cutoff_date = (datetime.utcnow() - timedelta(days=days_inactive)).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        endpoint = f"/deviceManagement/managedDevices?$filter=lastSyncDateTime le {cutoff_date}&$top={top}&$orderby=lastSyncDateTime asc"
        
        response = await client.get(endpoint)
        devices = response.get("value", [])
        
        return {
            "days_inactive_threshold": days_inactive,
            "count": len(devices),
            "stale_devices": [
                {
                    "id": d.get("id"),
                    "deviceName": d.get("deviceName"),
                    "userPrincipalName": d.get("userPrincipalName"),
                    "lastSyncDateTime": d.get("lastSyncDateTime"),
                    "operatingSystem": d.get("operatingSystem"),
                }
                for d in devices
            ]
        }
    
    @server.tool()
    async def delete_device(device_id: str, confirm: bool = False) -> dict[str, Any]:
        """
        Delete a managed device from Intune.
        
        Args:
            device_id: The Intune device ID
            confirm: Must be True to execute the deletion
        
        Returns:
            Status of the deletion
        """
        if not confirm:
            return {
                "status": "confirmation_required",
                "message": "⚠️ DELETE will remove the device record! Set confirm=True to proceed."
            }
        
        client = get_graph_client()
        
        # Get device info before deletion
        device = await client.get(f"/deviceManagement/managedDevices/{device_id}")
        device_name = device.get("deviceName", "Unknown")
        
        await client.delete(f"/deviceManagement/managedDevices/{device_id}")
        
        return {
            "status": "success",
            "message": f"Device '{device_name}' deleted from Intune",
            "device_id": device_id,
            "device_name": device_name
        }

