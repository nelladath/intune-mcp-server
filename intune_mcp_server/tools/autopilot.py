"""Autopilot Management Tools for Intune MCP Server."""

from typing import Any
from mcp.server import Server

from ..graph_client import get_graph_client


def register_autopilot_tools(server: Server):
    """Register all Autopilot management tools with the MCP server."""
    
    @server.tool()
    async def list_autopilot_devices(top: int = 50) -> dict[str, Any]:
        """
        List all Windows Autopilot devices.
        
        Args:
            top: Maximum number of devices to return
        
        Returns:
            List of Autopilot devices
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
                    "displayName": d.get("displayName"),
                    "serialNumber": d.get("serialNumber"),
                    "model": d.get("model"),
                    "manufacturer": d.get("manufacturer"),
                    "groupTag": d.get("groupTag"),
                    "purchaseOrderIdentifier": d.get("purchaseOrderIdentifier"),
                    "enrollmentState": d.get("enrollmentState"),
                    "lastContactedDateTime": d.get("lastContactedDateTime"),
                    "deploymentProfileAssignmentStatus": d.get("deploymentProfileAssignmentStatus"),
                    "deploymentProfileAssignedDateTime": d.get("deploymentProfileAssignedDateTime"),
                }
                for d in devices
            ]
        }
    
    @server.tool()
    async def get_autopilot_device(device_id: str) -> dict[str, Any]:
        """
        Get details of a specific Autopilot device.
        
        Args:
            device_id: The Autopilot device ID
        
        Returns:
            Detailed Autopilot device information
        """
        client = get_graph_client()
        
        device = await client.get(
            f"/deviceManagement/windowsAutopilotDeviceIdentities/{device_id}"
        )
        
        return {
            "id": device.get("id"),
            "displayName": device.get("displayName"),
            "serialNumber": device.get("serialNumber"),
            "productKey": device.get("productKey"),
            "hardwareIdentifier": "Present" if device.get("hardwareIdentifier") else "None",
            "model": device.get("model"),
            "manufacturer": device.get("manufacturer"),
            "groupTag": device.get("groupTag"),
            "purchaseOrderIdentifier": device.get("purchaseOrderIdentifier"),
            "resourceName": device.get("resourceName"),
            "skuNumber": device.get("skuNumber"),
            "systemFamily": device.get("systemFamily"),
            "azureActiveDirectoryDeviceId": device.get("azureActiveDirectoryDeviceId"),
            "managedDeviceId": device.get("managedDeviceId"),
            "enrollmentState": device.get("enrollmentState"),
            "lastContactedDateTime": device.get("lastContactedDateTime"),
            "addressableUserName": device.get("addressableUserName"),
            "userPrincipalName": device.get("userPrincipalName"),
            "deploymentProfileAssignmentStatus": device.get("deploymentProfileAssignmentStatus"),
            "deploymentProfileAssignedDateTime": device.get("deploymentProfileAssignedDateTime"),
        }
    
    @server.tool()
    async def search_autopilot_device(
        search_term: str,
        search_by: str = "serialNumber"
    ) -> dict[str, Any]:
        """
        Search for Autopilot devices by serial number or other fields.
        
        Args:
            search_term: The value to search for
            search_by: Field to search - "serialNumber", "model", "groupTag"
        
        Returns:
            List of matching Autopilot devices
        """
        client = get_graph_client()
        
        valid_fields = ["serialNumber", "model", "groupTag", "manufacturer"]
        if search_by not in valid_fields:
            return {"error": f"Invalid search field. Use one of: {valid_fields}"}
        
        endpoint = f"/deviceManagement/windowsAutopilotDeviceIdentities?$filter=contains({search_by}, '{search_term}')"
        
        response = await client.get(endpoint)
        devices = response.get("value", [])
        
        return {
            "search_term": search_term,
            "search_field": search_by,
            "count": len(devices),
            "devices": [
                {
                    "id": d.get("id"),
                    "serialNumber": d.get("serialNumber"),
                    "model": d.get("model"),
                    "manufacturer": d.get("manufacturer"),
                    "groupTag": d.get("groupTag"),
                    "enrollmentState": d.get("enrollmentState"),
                }
                for d in devices
            ]
        }
    
    @server.tool()
    async def list_autopilot_profiles() -> dict[str, Any]:
        """
        List all Windows Autopilot deployment profiles.
        
        Returns:
            List of Autopilot deployment profiles
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
                    "deviceNameTemplate": p.get("deviceNameTemplate"),
                    "deviceType": p.get("deviceType"),
                    "enableWhiteGlove": p.get("enableWhiteGlove"),
                    "extractHardwareHash": p.get("extractHardwareHash"),
                    "language": p.get("language"),
                    "createdDateTime": p.get("createdDateTime"),
                    "lastModifiedDateTime": p.get("lastModifiedDateTime"),
                }
                for p in profiles
            ]
        }
    
    @server.tool()
    async def get_autopilot_profile(profile_id: str) -> dict[str, Any]:
        """
        Get details of an Autopilot deployment profile.
        
        Args:
            profile_id: The Autopilot profile ID
        
        Returns:
            Detailed profile information
        """
        client = get_graph_client()
        
        profile = await client.get(
            f"/deviceManagement/windowsAutopilotDeploymentProfiles/{profile_id}"
        )
        
        # Get assignments
        try:
            assignments = await client.get(
                f"/deviceManagement/windowsAutopilotDeploymentProfiles/{profile_id}/assignments"
            )
            assignment_list = assignments.get("value", [])
        except Exception:
            assignment_list = []
        
        return {
            "profile": {
                "id": profile.get("id"),
                "displayName": profile.get("displayName"),
                "description": profile.get("description"),
                "deviceNameTemplate": profile.get("deviceNameTemplate"),
                "deviceType": profile.get("deviceType"),
                "enableWhiteGlove": profile.get("enableWhiteGlove"),
                "extractHardwareHash": profile.get("extractHardwareHash"),
                "language": profile.get("language"),
                "outOfBoxExperienceSettings": profile.get("outOfBoxExperienceSettings", {}),
                "createdDateTime": profile.get("createdDateTime"),
                "lastModifiedDateTime": profile.get("lastModifiedDateTime"),
            },
            "assignments": [
                {
                    "id": a.get("id"),
                    "targetType": a.get("target", {}).get("@odata.type", "").replace("#microsoft.graph.", ""),
                    "groupId": a.get("target", {}).get("groupId"),
                }
                for a in assignment_list
            ]
        }
    
    @server.tool()
    async def assign_autopilot_profile(
        profile_id: str,
        group_id: str
    ) -> dict[str, Any]:
        """
        Assign an Autopilot profile to a group.
        
        Args:
            profile_id: The Autopilot profile ID
            group_id: The Azure AD group ID
        
        Returns:
            Status of the assignment
        """
        client = get_graph_client()
        
        profile = await client.get(
            f"/deviceManagement/windowsAutopilotDeploymentProfiles/{profile_id}?$select=displayName"
        )
        group = await client.get(f"/groups/{group_id}?$select=displayName")
        
        assignment_body = {
            "target": {
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": group_id
            }
        }
        
        await client.post(
            f"/deviceManagement/windowsAutopilotDeploymentProfiles/{profile_id}/assignments",
            json=assignment_body
        )
        
        return {
            "status": "success",
            "message": f"Profile '{profile.get('displayName')}' assigned to group '{group.get('displayName')}'",
            "profile_id": profile_id,
            "group_id": group_id
        }
    
    @server.tool()
    async def update_autopilot_device_group_tag(
        device_id: str,
        group_tag: str
    ) -> dict[str, Any]:
        """
        Update the group tag of an Autopilot device.
        
        Args:
            device_id: The Autopilot device ID
            group_tag: The new group tag
        
        Returns:
            Status of the update
        """
        client = get_graph_client()
        
        # Get current device info
        device = await client.get(
            f"/deviceManagement/windowsAutopilotDeviceIdentities/{device_id}"
        )
        old_tag = device.get("groupTag", "")
        
        # Update group tag
        await client.post(
            f"/deviceManagement/windowsAutopilotDeviceIdentities/{device_id}/updateDeviceProperties",
            json={
                "groupTag": group_tag
            }
        )
        
        return {
            "status": "success",
            "message": f"Group tag updated for device {device.get('serialNumber')}",
            "device_id": device_id,
            "serial_number": device.get("serialNumber"),
            "old_group_tag": old_tag,
            "new_group_tag": group_tag
        }
    
    @server.tool()
    async def delete_autopilot_device(
        device_id: str,
        confirm: bool = False
    ) -> dict[str, Any]:
        """
        Delete an Autopilot device.
        
        Args:
            device_id: The Autopilot device ID
            confirm: Must be True to execute deletion
        
        Returns:
            Status of the deletion
        """
        if not confirm:
            return {
                "status": "confirmation_required",
                "message": "⚠️ Set confirm=True to delete this Autopilot device"
            }
        
        client = get_graph_client()
        
        device = await client.get(
            f"/deviceManagement/windowsAutopilotDeviceIdentities/{device_id}"
        )
        serial = device.get("serialNumber", "Unknown")
        
        await client.delete(
            f"/deviceManagement/windowsAutopilotDeviceIdentities/{device_id}"
        )
        
        return {
            "status": "success",
            "message": f"Autopilot device '{serial}' deleted",
            "device_id": device_id,
            "serial_number": serial
        }
    
    @server.tool()
    async def sync_autopilot_devices() -> dict[str, Any]:
        """
        Trigger a sync of Autopilot devices from the partner portal.
        
        Returns:
            Status of the sync request
        """
        client = get_graph_client()
        
        await client.post("/deviceManagement/windowsAutopilotSettings/sync")
        
        return {
            "status": "success",
            "message": "Autopilot device sync initiated",
            "note": "This syncs devices from hardware vendors. It may take a few minutes."
        }
    
    @server.tool()
    async def get_autopilot_settings() -> dict[str, Any]:
        """
        Get Windows Autopilot settings.
        
        Returns:
            Autopilot settings including sync status
        """
        client = get_graph_client()
        
        settings = await client.get("/deviceManagement/windowsAutopilotSettings")
        
        return {
            "lastSyncDateTime": settings.get("lastSyncDateTime"),
            "lastManualSyncTriggerDateTime": settings.get("lastManualSyncTriggerDateTime"),
            "syncStatus": settings.get("syncStatus"),
        }
    
    @server.tool()
    async def get_enrollment_status_page() -> dict[str, Any]:
        """
        Get Enrollment Status Page configurations.
        
        Returns:
            List of ESP configurations
        """
        client = get_graph_client()
        
        response = await client.get(
            "/deviceManagement/deviceEnrollmentConfigurations?$filter=isof('microsoft.graph.windows10EnrollmentCompletionPageConfiguration')"
        )
        configs = response.get("value", [])
        
        return {
            "count": len(configs),
            "esp_configurations": [
                {
                    "id": c.get("id"),
                    "displayName": c.get("displayName"),
                    "description": c.get("description"),
                    "showInstallationProgress": c.get("showInstallationProgress"),
                    "blockDeviceSetupRetryByUser": c.get("blockDeviceSetupRetryByUser"),
                    "allowDeviceResetOnInstallFailure": c.get("allowDeviceResetOnInstallFailure"),
                    "installProgressTimeoutInMinutes": c.get("installProgressTimeoutInMinutes"),
                    "createdDateTime": c.get("createdDateTime"),
                }
                for c in configs
            ]
        }

