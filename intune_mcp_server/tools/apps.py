"""App Management Tools for Intune MCP Server."""

from typing import Any
from mcp.server import Server

from ..graph_client import get_graph_client


def register_app_tools(server: Server):
    """Register all app management tools with the MCP server."""
    
    @server.tool()
    async def list_mobile_apps(
        app_type: str = "",
        top: int = 50
    ) -> dict[str, Any]:
        """
        List all mobile apps in Intune.
        
        Args:
            app_type: Filter by type (e.g., "microsoftStoreForBusinessApp", "win32LobApp", "iosStoreApp")
            top: Maximum number of apps to return
        
        Returns:
            List of mobile apps
        """
        client = get_graph_client()
        
        endpoint = f"/deviceAppManagement/mobileApps?$top={top}"
        if app_type:
            endpoint += f"&$filter=isof('{app_type}')"
        
        response = await client.get(endpoint)
        apps = response.get("value", [])
        
        return {
            "count": len(apps),
            "apps": [
                {
                    "id": app.get("id"),
                    "displayName": app.get("displayName"),
                    "description": app.get("description"),
                    "publisher": app.get("publisher"),
                    "appType": app.get("@odata.type", "").replace("#microsoft.graph.", ""),
                    "createdDateTime": app.get("createdDateTime"),
                    "lastModifiedDateTime": app.get("lastModifiedDateTime"),
                    "isFeatured": app.get("isFeatured"),
                    "privacyInformationUrl": app.get("privacyInformationUrl"),
                }
                for app in apps
            ]
        }
    
    @server.tool()
    async def get_app_details(app_id: str) -> dict[str, Any]:
        """
        Get detailed information about a specific app.
        
        Args:
            app_id: The Intune app ID
        
        Returns:
            Comprehensive app details
        """
        client = get_graph_client()
        
        app = await client.get(f"/deviceAppManagement/mobileApps/{app_id}")
        
        # Get assignments
        try:
            assignments = await client.get(
                f"/deviceAppManagement/mobileApps/{app_id}/assignments"
            )
            assignment_list = assignments.get("value", [])
        except Exception:
            assignment_list = []
        
        return {
            "app_info": {
                "id": app.get("id"),
                "displayName": app.get("displayName"),
                "description": app.get("description"),
                "publisher": app.get("publisher"),
                "appType": app.get("@odata.type", "").replace("#microsoft.graph.", ""),
                "createdDateTime": app.get("createdDateTime"),
                "lastModifiedDateTime": app.get("lastModifiedDateTime"),
                "isFeatured": app.get("isFeatured"),
                "largeIcon": "Present" if app.get("largeIcon") else "None",
            },
            "publishing_info": {
                "publishingState": app.get("publishingState"),
                "isAssigned": app.get("isAssigned"),
                "roleScopeTagIds": app.get("roleScopeTagIds"),
            },
            "assignments": [
                {
                    "id": a.get("id"),
                    "intent": a.get("intent"),
                    "targetType": a.get("target", {}).get("@odata.type", "").replace("#microsoft.graph.", ""),
                    "groupId": a.get("target", {}).get("groupId"),
                }
                for a in assignment_list
            ]
        }
    
    @server.tool()
    async def search_apps(search_term: str) -> dict[str, Any]:
        """
        Search for apps by name.
        
        Args:
            search_term: The app name to search for
        
        Returns:
            List of matching apps
        """
        client = get_graph_client()
        
        # Use filter with contains for searching
        endpoint = f"/deviceAppManagement/mobileApps?$filter=contains(displayName, '{search_term}')&$top=50"
        
        response = await client.get(endpoint)
        apps = response.get("value", [])
        
        return {
            "search_term": search_term,
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
    
    @server.tool()
    async def get_app_assignments(app_id: str) -> dict[str, Any]:
        """
        Get all assignments for an app.
        
        Args:
            app_id: The Intune app ID
        
        Returns:
            List of app assignments with group details
        """
        client = get_graph_client()
        
        # Get app info
        app = await client.get(f"/deviceAppManagement/mobileApps/{app_id}?$select=displayName")
        
        # Get assignments
        assignments = await client.get(
            f"/deviceAppManagement/mobileApps/{app_id}/assignments"
        )
        assignment_list = assignments.get("value", [])
        
        # Enrich with group names where possible
        enriched_assignments = []
        for a in assignment_list:
            assignment_info = {
                "id": a.get("id"),
                "intent": a.get("intent"),
                "targetType": a.get("target", {}).get("@odata.type", "").replace("#microsoft.graph.", ""),
            }
            
            group_id = a.get("target", {}).get("groupId")
            if group_id:
                try:
                    group = await client.get(f"/groups/{group_id}?$select=displayName")
                    assignment_info["groupName"] = group.get("displayName")
                    assignment_info["groupId"] = group_id
                except Exception:
                    assignment_info["groupId"] = group_id
            
            enriched_assignments.append(assignment_info)
        
        return {
            "app_name": app.get("displayName"),
            "app_id": app_id,
            "assignment_count": len(enriched_assignments),
            "assignments": enriched_assignments
        }
    
    @server.tool()
    async def assign_app_to_group(
        app_id: str,
        group_id: str,
        intent: str = "required"
    ) -> dict[str, Any]:
        """
        Assign an app to a group.
        
        Args:
            app_id: The Intune app ID
            group_id: The Azure AD group ID
            intent: Assignment intent - "required", "available", "uninstall"
        
        Returns:
            Status of the assignment
        """
        client = get_graph_client()
        
        valid_intents = ["required", "available", "uninstall", "availableWithoutEnrollment"]
        if intent not in valid_intents:
            return {"error": f"Invalid intent. Use one of: {valid_intents}"}
        
        # Get app and group info for confirmation
        app = await client.get(f"/deviceAppManagement/mobileApps/{app_id}?$select=displayName")
        group = await client.get(f"/groups/{group_id}?$select=displayName")
        
        # Create assignment
        assignment_body = {
            "mobileAppAssignments": [
                {
                    "@odata.type": "#microsoft.graph.mobileAppAssignment",
                    "intent": intent,
                    "target": {
                        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                        "groupId": group_id
                    }
                }
            ]
        }
        
        await client.post(
            f"/deviceAppManagement/mobileApps/{app_id}/assign",
            json=assignment_body
        )
        
        return {
            "status": "success",
            "message": f"App '{app.get('displayName')}' assigned to group '{group.get('displayName')}'",
            "app_id": app_id,
            "group_id": group_id,
            "intent": intent
        }
    
    @server.tool()
    async def remove_app_assignment(
        app_id: str,
        assignment_id: str
    ) -> dict[str, Any]:
        """
        Remove an app assignment.
        
        Args:
            app_id: The Intune app ID
            assignment_id: The assignment ID to remove
        
        Returns:
            Status of the removal
        """
        client = get_graph_client()
        
        app = await client.get(f"/deviceAppManagement/mobileApps/{app_id}?$select=displayName")
        
        await client.delete(
            f"/deviceAppManagement/mobileApps/{app_id}/assignments/{assignment_id}"
        )
        
        return {
            "status": "success",
            "message": f"Assignment removed from app '{app.get('displayName')}'",
            "app_id": app_id,
            "assignment_id": assignment_id
        }
    
    @server.tool()
    async def get_app_installation_status(app_id: str, top: int = 50) -> dict[str, Any]:
        """
        Get installation status for an app across devices.
        
        Args:
            app_id: The Intune app ID
            top: Maximum number of status records to return
        
        Returns:
            Installation status summary and device details
        """
        client = get_graph_client()
        
        app = await client.get(f"/deviceAppManagement/mobileApps/{app_id}?$select=displayName")
        
        # Get device statuses
        statuses = await client.get(
            f"/deviceAppManagement/mobileApps/{app_id}/deviceStatuses?$top={top}"
        )
        status_list = statuses.get("value", [])
        
        # Summarize by status
        status_summary = {}
        for s in status_list:
            install_state = s.get("installState", "unknown")
            status_summary[install_state] = status_summary.get(install_state, 0) + 1
        
        return {
            "app_name": app.get("displayName"),
            "app_id": app_id,
            "status_summary": status_summary,
            "total_devices": len(status_list),
            "device_statuses": [
                {
                    "deviceName": s.get("deviceName"),
                    "deviceId": s.get("deviceId"),
                    "installState": s.get("installState"),
                    "installStateDetail": s.get("installStateDetail"),
                    "lastSyncDateTime": s.get("lastSyncDateTime"),
                    "errorCode": s.get("errorCode"),
                }
                for s in status_list[:20]  # Limit detailed list
            ]
        }
    
    @server.tool()
    async def list_win32_apps() -> dict[str, Any]:
        """
        List all Win32 LOB apps in Intune.
        
        Returns:
            List of Win32 apps with details
        """
        client = get_graph_client()
        
        endpoint = "/deviceAppManagement/mobileApps?$filter=isof('microsoft.graph.win32LobApp')&$top=100"
        
        response = await client.get(endpoint)
        apps = response.get("value", [])
        
        return {
            "count": len(apps),
            "win32_apps": [
                {
                    "id": app.get("id"),
                    "displayName": app.get("displayName"),
                    "publisher": app.get("publisher"),
                    "fileName": app.get("fileName"),
                    "installCommandLine": app.get("installCommandLine"),
                    "uninstallCommandLine": app.get("uninstallCommandLine"),
                    "createdDateTime": app.get("createdDateTime"),
                }
                for app in apps
            ]
        }
    
    @server.tool()
    async def list_app_categories() -> dict[str, Any]:
        """
        List all app categories in Intune.
        
        Returns:
            List of app categories
        """
        client = get_graph_client()
        
        response = await client.get("/deviceAppManagement/mobileAppCategories")
        categories = response.get("value", [])
        
        return {
            "count": len(categories),
            "categories": [
                {
                    "id": cat.get("id"),
                    "displayName": cat.get("displayName"),
                    "lastModifiedDateTime": cat.get("lastModifiedDateTime"),
                }
                for cat in categories
            ]
        }
    
    @server.tool()
    async def get_device_app_installations(device_id: str) -> dict[str, Any]:
        """
        Get all app installations on a specific device.
        
        Args:
            device_id: The Intune device ID
        
        Returns:
            List of apps installed or assigned to the device
        """
        client = get_graph_client()
        
        # Get device info
        device = await client.get(
            f"/deviceManagement/managedDevices/{device_id}?$select=deviceName,userPrincipalName"
        )
        
        # Get detected apps
        detected = await client.get(
            f"/deviceManagement/managedDevices/{device_id}/detectedApps"
        )
        detected_apps = detected.get("value", [])
        
        return {
            "device_name": device.get("deviceName"),
            "user": device.get("userPrincipalName"),
            "detected_apps_count": len(detected_apps),
            "detected_apps": [
                {
                    "displayName": app.get("displayName"),
                    "version": app.get("version"),
                    "sizeInByte": app.get("sizeInByte"),
                    "deviceCount": app.get("deviceCount"),
                }
                for app in detected_apps[:50]  # Limit to first 50
            ]
        }

