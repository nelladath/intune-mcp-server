"""User and Group Management Tools for Intune MCP Server."""

from typing import Any
from mcp.server import Server

from ..graph_client import get_graph_client


def register_user_tools(server: Server):
    """Register all user and group management tools with the MCP server."""
    
    @server.tool()
    async def get_user(user_id: str) -> dict[str, Any]:
        """
        Get details of a user by ID or UPN.
        
        Args:
            user_id: The user ID or userPrincipalName
        
        Returns:
            User details
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
            "officeLocation": user.get("officeLocation"),
            "mobilePhone": user.get("mobilePhone"),
            "businessPhones": user.get("businessPhones"),
            "accountEnabled": user.get("accountEnabled"),
            "createdDateTime": user.get("createdDateTime"),
        }
    
    @server.tool()
    async def search_users(
        search_term: str,
        search_by: str = "displayName"
    ) -> dict[str, Any]:
        """
        Search for users by name, email, or UPN.
        
        Args:
            search_term: The value to search for
            search_by: Field to search - "displayName", "mail", "userPrincipalName"
        
        Returns:
            List of matching users
        """
        client = get_graph_client()
        
        valid_fields = ["displayName", "mail", "userPrincipalName"]
        if search_by not in valid_fields:
            return {"error": f"Invalid search field. Use one of: {valid_fields}"}
        
        endpoint = f"/users?$filter=startswith({search_by}, '{search_term}')&$top=50"
        
        response = await client.get(endpoint)
        users = response.get("value", [])
        
        return {
            "search_term": search_term,
            "search_field": search_by,
            "count": len(users),
            "users": [
                {
                    "id": u.get("id"),
                    "displayName": u.get("displayName"),
                    "userPrincipalName": u.get("userPrincipalName"),
                    "mail": u.get("mail"),
                    "department": u.get("department"),
                    "accountEnabled": u.get("accountEnabled"),
                }
                for u in users
            ]
        }
    
    @server.tool()
    async def get_user_devices(user_id: str) -> dict[str, Any]:
        """
        Get all managed devices for a specific user.
        
        Args:
            user_id: The user ID or userPrincipalName
        
        Returns:
            List of user's managed devices
        """
        client = get_graph_client()
        
        # Get user info
        user = await client.get(f"/users/{user_id}?$select=displayName,userPrincipalName")
        
        # Get managed devices for user
        devices = await client.get(
            f"/deviceManagement/managedDevices?$filter=userPrincipalName eq '{user['userPrincipalName']}'"
        )
        device_list = devices.get("value", [])
        
        return {
            "user": {
                "displayName": user.get("displayName"),
                "userPrincipalName": user.get("userPrincipalName"),
            },
            "device_count": len(device_list),
            "devices": [
                {
                    "id": d.get("id"),
                    "deviceName": d.get("deviceName"),
                    "operatingSystem": d.get("operatingSystem"),
                    "osVersion": d.get("osVersion"),
                    "complianceState": d.get("complianceState"),
                    "lastSyncDateTime": d.get("lastSyncDateTime"),
                    "serialNumber": d.get("serialNumber"),
                }
                for d in device_list
            ]
        }
    
    @server.tool()
    async def list_groups(top: int = 50, filter_query: str = "") -> dict[str, Any]:
        """
        List Azure AD groups.
        
        Args:
            top: Maximum number of groups to return
            filter_query: OData filter (e.g., "displayName eq 'IT Department'")
        
        Returns:
            List of groups
        """
        client = get_graph_client()
        
        endpoint = f"/groups?$top={top}"
        if filter_query:
            endpoint += f"&$filter={filter_query}"
        
        response = await client.get(endpoint)
        groups = response.get("value", [])
        
        return {
            "count": len(groups),
            "groups": [
                {
                    "id": g.get("id"),
                    "displayName": g.get("displayName"),
                    "description": g.get("description"),
                    "groupTypes": g.get("groupTypes"),
                    "membershipRule": g.get("membershipRule"),
                    "securityEnabled": g.get("securityEnabled"),
                    "mailEnabled": g.get("mailEnabled"),
                    "createdDateTime": g.get("createdDateTime"),
                }
                for g in groups
            ]
        }
    
    @server.tool()
    async def search_groups(search_term: str) -> dict[str, Any]:
        """
        Search for groups by name.
        
        Args:
            search_term: The group name to search for
        
        Returns:
            List of matching groups
        """
        client = get_graph_client()
        
        endpoint = f"/groups?$filter=startswith(displayName, '{search_term}')&$top=50"
        
        response = await client.get(endpoint)
        groups = response.get("value", [])
        
        return {
            "search_term": search_term,
            "count": len(groups),
            "groups": [
                {
                    "id": g.get("id"),
                    "displayName": g.get("displayName"),
                    "description": g.get("description"),
                    "groupTypes": g.get("groupTypes"),
                    "securityEnabled": g.get("securityEnabled"),
                }
                for g in groups
            ]
        }
    
    @server.tool()
    async def get_group(group_id: str) -> dict[str, Any]:
        """
        Get details of a specific group.
        
        Args:
            group_id: The group ID
        
        Returns:
            Group details
        """
        client = get_graph_client()
        
        group = await client.get(f"/groups/{group_id}")
        
        # Get member count
        try:
            members = await client.get(f"/groups/{group_id}/members?$count=true&$top=1")
            member_count = members.get("@odata.count", len(members.get("value", [])))
        except Exception:
            member_count = "Unknown"
        
        return {
            "id": group.get("id"),
            "displayName": group.get("displayName"),
            "description": group.get("description"),
            "groupTypes": group.get("groupTypes"),
            "membershipRule": group.get("membershipRule"),
            "membershipRuleProcessingState": group.get("membershipRuleProcessingState"),
            "securityEnabled": group.get("securityEnabled"),
            "mailEnabled": group.get("mailEnabled"),
            "mail": group.get("mail"),
            "createdDateTime": group.get("createdDateTime"),
            "member_count": member_count,
        }
    
    @server.tool()
    async def get_group_members(
        group_id: str,
        top: int = 50
    ) -> dict[str, Any]:
        """
        Get members of a group.
        
        Args:
            group_id: The group ID
            top: Maximum number of members to return
        
        Returns:
            List of group members
        """
        client = get_graph_client()
        
        group = await client.get(f"/groups/{group_id}?$select=displayName")
        
        members = await client.get(f"/groups/{group_id}/members?$top={top}")
        member_list = members.get("value", [])
        
        return {
            "group_name": group.get("displayName"),
            "group_id": group_id,
            "member_count": len(member_list),
            "members": [
                {
                    "id": m.get("id"),
                    "displayName": m.get("displayName"),
                    "userPrincipalName": m.get("userPrincipalName"),
                    "memberType": m.get("@odata.type", "").replace("#microsoft.graph.", ""),
                }
                for m in member_list
            ]
        }
    
    @server.tool()
    async def add_user_to_group(
        user_id: str,
        group_id: str
    ) -> dict[str, Any]:
        """
        Add a user to a group.
        
        Args:
            user_id: The user ID or UPN
            group_id: The group ID
        
        Returns:
            Status of the operation
        """
        client = get_graph_client()
        
        user = await client.get(f"/users/{user_id}?$select=displayName,id")
        group = await client.get(f"/groups/{group_id}?$select=displayName")
        
        await client.post(
            f"/groups/{group_id}/members/$ref",
            json={
                "@odata.id": f"https://graph.microsoft.com/v1.0/users/{user['id']}"
            }
        )
        
        return {
            "status": "success",
            "message": f"User '{user.get('displayName')}' added to group '{group.get('displayName')}'",
            "user_id": user.get("id"),
            "group_id": group_id
        }
    
    @server.tool()
    async def remove_user_from_group(
        user_id: str,
        group_id: str
    ) -> dict[str, Any]:
        """
        Remove a user from a group.
        
        Args:
            user_id: The user ID
            group_id: The group ID
        
        Returns:
            Status of the operation
        """
        client = get_graph_client()
        
        user = await client.get(f"/users/{user_id}?$select=displayName")
        group = await client.get(f"/groups/{group_id}?$select=displayName")
        
        await client.delete(f"/groups/{group_id}/members/{user_id}/$ref")
        
        return {
            "status": "success",
            "message": f"User '{user.get('displayName')}' removed from group '{group.get('displayName')}'",
            "user_id": user_id,
            "group_id": group_id
        }
    
    @server.tool()
    async def get_user_group_memberships(user_id: str) -> dict[str, Any]:
        """
        Get all group memberships for a user.
        
        Args:
            user_id: The user ID or UPN
        
        Returns:
            List of groups the user is a member of
        """
        client = get_graph_client()
        
        user = await client.get(f"/users/{user_id}?$select=displayName,userPrincipalName")
        
        memberships = await client.get(f"/users/{user_id}/memberOf")
        groups = memberships.get("value", [])
        
        return {
            "user": {
                "displayName": user.get("displayName"),
                "userPrincipalName": user.get("userPrincipalName"),
            },
            "group_count": len(groups),
            "groups": [
                {
                    "id": g.get("id"),
                    "displayName": g.get("displayName"),
                    "type": g.get("@odata.type", "").replace("#microsoft.graph.", ""),
                }
                for g in groups
                if g.get("@odata.type") == "#microsoft.graph.group"
            ]
        }
    
    @server.tool()
    async def get_user_licenses(user_id: str) -> dict[str, Any]:
        """
        Get license assignments for a user.
        
        Args:
            user_id: The user ID or UPN
        
        Returns:
            List of assigned licenses
        """
        client = get_graph_client()
        
        user = await client.get(
            f"/users/{user_id}?$select=displayName,userPrincipalName,assignedLicenses,licenseAssignmentStates"
        )
        
        return {
            "user": {
                "displayName": user.get("displayName"),
                "userPrincipalName": user.get("userPrincipalName"),
            },
            "licenses": user.get("assignedLicenses", []),
            "license_states": user.get("licenseAssignmentStates", [])
        }
    
    @server.tool()
    async def get_directory_role_members(role_name: str) -> dict[str, Any]:
        """
        Get members of a directory role (e.g., Global Administrator, Intune Administrator).
        
        Args:
            role_name: The role name to search for (e.g., "Intune", "Global")
        
        Returns:
            List of users with the specified role
        """
        client = get_graph_client()
        
        # Get directory roles
        roles = await client.get(
            f"/directoryRoles?$filter=contains(displayName, '{role_name}')"
        )
        role_list = roles.get("value", [])
        
        results = []
        for role in role_list:
            members = await client.get(f"/directoryRoles/{role['id']}/members")
            member_list = members.get("value", [])
            
            results.append({
                "role_name": role.get("displayName"),
                "role_id": role.get("id"),
                "member_count": len(member_list),
                "members": [
                    {
                        "id": m.get("id"),
                        "displayName": m.get("displayName"),
                        "userPrincipalName": m.get("userPrincipalName"),
                    }
                    for m in member_list
                ]
            })
        
        return {
            "search_term": role_name,
            "roles_found": len(results),
            "roles": results
        }

