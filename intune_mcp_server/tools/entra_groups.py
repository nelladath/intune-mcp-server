"""
Entra ID (Azure AD) Group Management Tools
Comprehensive group management including CRUD, membership, and dynamic groups.
"""

from typing import Any
from ..graph_client import get_graph_client


async def list_all_groups(
    top: int = 50,
    filter_query: str = "",
    group_type: str = ""
) -> dict[str, Any]:
    """
    List all groups in the tenant.
    
    Args:
        top: Maximum number of groups to return (default 50)
        filter_query: OData filter query
        group_type: Filter by type - "security", "microsoft365", "dynamic", "all"
    
    Returns:
        List of groups
    """
    client = get_graph_client()
    
    endpoint = "/groups"
    params = [f"$top={min(top, 999)}"]
    
    # Build filter based on group type
    filters = []
    if filter_query:
        filters.append(filter_query)
    
    if group_type == "security":
        filters.append("securityEnabled eq true and mailEnabled eq false")
    elif group_type == "microsoft365":
        filters.append("groupTypes/any(c:c eq 'Unified')")
    elif group_type == "dynamic":
        filters.append("groupTypes/any(c:c eq 'DynamicMembership')")
    
    if filters:
        params.append(f"$filter={' and '.join(filters)}")
    
    params.append("$select=id,displayName,description,groupTypes,membershipRule,securityEnabled,mailEnabled,mail,createdDateTime")
    
    endpoint += "?" + "&".join(params)
    
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
                "mail": g.get("mail"),
                "isDynamic": "DynamicMembership" in g.get("groupTypes", []),
                "isM365": "Unified" in g.get("groupTypes", []),
                "createdDateTime": g.get("createdDateTime"),
            }
            for g in groups
        ]
    }


async def get_group_details(group_id: str) -> dict[str, Any]:
    """
    Get comprehensive details for a specific group.
    
    Args:
        group_id: The group ID
    
    Returns:
        Complete group information
    """
    client = get_graph_client()
    
    group = await client.get(f"/groups/{group_id}")
    
    # Get member count
    try:
        members = await client.get(f"/groups/{group_id}/members/$count", headers={"ConsistencyLevel": "eventual"})
        member_count = members if isinstance(members, int) else len((await client.get(f"/groups/{group_id}/members?$top=1")).get("value", []))
    except:
        try:
            members_resp = await client.get(f"/groups/{group_id}/members?$top=999")
            member_count = len(members_resp.get("value", []))
        except:
            member_count = "Unknown"
    
    # Get owners
    try:
        owners = await client.get(f"/groups/{group_id}/owners")
        owner_list = owners.get("value", [])
    except:
        owner_list = []
    
    return {
        "basic_info": {
            "id": group.get("id"),
            "displayName": group.get("displayName"),
            "description": group.get("description"),
            "mail": group.get("mail"),
            "mailNickname": group.get("mailNickname"),
        },
        "group_type": {
            "groupTypes": group.get("groupTypes"),
            "securityEnabled": group.get("securityEnabled"),
            "mailEnabled": group.get("mailEnabled"),
            "isAssignableToRole": group.get("isAssignableToRole"),
            "isDynamic": "DynamicMembership" in group.get("groupTypes", []),
            "isM365Group": "Unified" in group.get("groupTypes", []),
        },
        "membership": {
            "membershipRule": group.get("membershipRule"),
            "membershipRuleProcessingState": group.get("membershipRuleProcessingState"),
            "member_count": member_count,
        },
        "owners": [
            {
                "id": o.get("id"),
                "displayName": o.get("displayName"),
                "userPrincipalName": o.get("userPrincipalName"),
            }
            for o in owner_list
        ],
        "settings": {
            "visibility": group.get("visibility"),
            "createdDateTime": group.get("createdDateTime"),
            "renewedDateTime": group.get("renewedDateTime"),
            "expirationDateTime": group.get("expirationDateTime"),
        }
    }


async def create_security_group(
    display_name: str,
    description: str = "",
    mail_nickname: str = None,
    is_assignable_to_role: bool = False
) -> dict[str, Any]:
    """
    Create a new security group.
    
    Args:
        display_name: Group display name
        description: Group description
        mail_nickname: Mail alias (auto-generated if not provided)
        is_assignable_to_role: Whether group can be assigned to Azure AD roles
    
    Returns:
        Created group details
    """
    client = get_graph_client()
    
    if not mail_nickname:
        mail_nickname = display_name.replace(" ", "").lower()[:64]
    
    group_data = {
        "displayName": display_name,
        "description": description,
        "mailNickname": mail_nickname,
        "mailEnabled": False,
        "securityEnabled": True,
        "isAssignableToRole": is_assignable_to_role
    }
    
    result = await client.post("/groups", json=group_data)
    
    return {
        "status": "success",
        "message": f"Security group '{display_name}' created successfully",
        "group": {
            "id": result.get("id"),
            "displayName": result.get("displayName"),
        }
    }


async def create_microsoft365_group(
    display_name: str,
    description: str = "",
    mail_nickname: str = None,
    visibility: str = "Private",
    owners: list = None
) -> dict[str, Any]:
    """
    Create a new Microsoft 365 group.
    
    Args:
        display_name: Group display name
        description: Group description
        mail_nickname: Mail alias (auto-generated if not provided)
        visibility: "Private" or "Public"
        owners: List of owner user IDs
    
    Returns:
        Created group details
    """
    client = get_graph_client()
    
    if not mail_nickname:
        mail_nickname = display_name.replace(" ", "").lower()[:64]
    
    group_data = {
        "displayName": display_name,
        "description": description,
        "mailNickname": mail_nickname,
        "mailEnabled": True,
        "securityEnabled": False,
        "groupTypes": ["Unified"],
        "visibility": visibility
    }
    
    if owners:
        group_data["owners@odata.bind"] = [
            f"https://graph.microsoft.com/v1.0/users/{owner_id}"
            for owner_id in owners
        ]
    
    result = await client.post("/groups", json=group_data)
    
    return {
        "status": "success",
        "message": f"Microsoft 365 group '{display_name}' created successfully",
        "group": {
            "id": result.get("id"),
            "displayName": result.get("displayName"),
            "mail": result.get("mail"),
        }
    }


async def create_dynamic_security_group(
    display_name: str,
    membership_rule: str,
    description: str = "",
    mail_nickname: str = None
) -> dict[str, Any]:
    """
    Create a dynamic security group with automatic membership based on a rule.
    
    Args:
        display_name: Group display name
        membership_rule: Dynamic membership rule (e.g., "user.department -eq 'IT'")
        description: Group description
        mail_nickname: Mail alias
    
    Returns:
        Created group details
    """
    client = get_graph_client()
    
    if not mail_nickname:
        mail_nickname = display_name.replace(" ", "").lower()[:64]
    
    group_data = {
        "displayName": display_name,
        "description": description,
        "mailNickname": mail_nickname,
        "mailEnabled": False,
        "securityEnabled": True,
        "groupTypes": ["DynamicMembership"],
        "membershipRule": membership_rule,
        "membershipRuleProcessingState": "On"
    }
    
    result = await client.post("/groups", json=group_data)
    
    return {
        "status": "success",
        "message": f"Dynamic security group '{display_name}' created successfully",
        "group": {
            "id": result.get("id"),
            "displayName": result.get("displayName"),
            "membershipRule": result.get("membershipRule"),
        }
    }


async def update_group(
    group_id: str,
    display_name: str = None,
    description: str = None,
    visibility: str = None,
    membership_rule: str = None
) -> dict[str, Any]:
    """
    Update group properties.
    
    Args:
        group_id: The group ID
        display_name: New display name
        description: New description
        visibility: New visibility (for M365 groups)
        membership_rule: New membership rule (for dynamic groups)
    
    Returns:
        Update status
    """
    client = get_graph_client()
    
    update_data = {}
    if display_name is not None:
        update_data["displayName"] = display_name
    if description is not None:
        update_data["description"] = description
    if visibility is not None:
        update_data["visibility"] = visibility
    if membership_rule is not None:
        update_data["membershipRule"] = membership_rule
    
    if not update_data:
        return {"status": "error", "message": "No fields provided for update"}
    
    group = await client.get(f"/groups/{group_id}?$select=displayName")
    
    await client.patch(f"/groups/{group_id}", json=update_data)
    
    return {
        "status": "success",
        "message": f"Group '{group.get('displayName')}' updated successfully",
        "updated_fields": list(update_data.keys())
    }


async def delete_group(group_id: str, confirm: bool = False) -> dict[str, Any]:
    """
    Delete a group.
    
    Args:
        group_id: The group ID
        confirm: Must be True to execute deletion
    
    Returns:
        Deletion status
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "⚠️ DELETE will remove the group! Set confirm=True to proceed."
        }
    
    client = get_graph_client()
    
    group = await client.get(f"/groups/{group_id}?$select=displayName")
    
    await client.delete(f"/groups/{group_id}")
    
    return {
        "status": "success",
        "message": f"Group '{group.get('displayName')}' deleted"
    }


async def get_group_members(group_id: str, top: int = 100) -> dict[str, Any]:
    """
    Get all members of a group.
    
    Args:
        group_id: The group ID
        top: Maximum number of members to return
    
    Returns:
        List of group members
    """
    client = get_graph_client()
    
    group = await client.get(f"/groups/{group_id}?$select=displayName")
    
    response = await client.get(f"/groups/{group_id}/members?$top={top}")
    members = response.get("value", [])
    
    return {
        "group_name": group.get("displayName"),
        "group_id": group_id,
        "member_count": len(members),
        "members": [
            {
                "id": m.get("id"),
                "displayName": m.get("displayName"),
                "userPrincipalName": m.get("userPrincipalName"),
                "mail": m.get("mail"),
                "type": m.get("@odata.type", "").replace("#microsoft.graph.", ""),
            }
            for m in members
        ]
    }


async def add_group_member(group_id: str, member_id: str) -> dict[str, Any]:
    """
    Add a member to a group.
    
    Args:
        group_id: The group ID
        member_id: The user or group ID to add
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    group = await client.get(f"/groups/{group_id}?$select=displayName")
    member = await client.get(f"/directoryObjects/{member_id}?$select=displayName")
    
    await client.post(
        f"/groups/{group_id}/members/$ref",
        json={"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{member_id}"}
    )
    
    return {
        "status": "success",
        "message": f"'{member.get('displayName')}' added to group '{group.get('displayName')}'"
    }


async def remove_group_member(group_id: str, member_id: str) -> dict[str, Any]:
    """
    Remove a member from a group.
    
    Args:
        group_id: The group ID
        member_id: The member ID to remove
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    group = await client.get(f"/groups/{group_id}?$select=displayName")
    
    await client.delete(f"/groups/{group_id}/members/{member_id}/$ref")
    
    return {
        "status": "success",
        "message": f"Member removed from group '{group.get('displayName')}'"
    }


async def add_group_members_bulk(group_id: str, member_ids: list) -> dict[str, Any]:
    """
    Add multiple members to a group at once.
    
    Args:
        group_id: The group ID
        member_ids: List of user/group IDs to add
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    group = await client.get(f"/groups/{group_id}?$select=displayName")
    
    # Graph API supports up to 20 members per request
    batch_size = 20
    added_count = 0
    errors = []
    
    for i in range(0, len(member_ids), batch_size):
        batch = member_ids[i:i + batch_size]
        
        try:
            await client.patch(
                f"/groups/{group_id}",
                json={
                    "members@odata.bind": [
                        f"https://graph.microsoft.com/v1.0/directoryObjects/{mid}"
                        for mid in batch
                    ]
                }
            )
            added_count += len(batch)
        except Exception as e:
            errors.append(f"Batch {i//batch_size + 1}: {str(e)}")
    
    return {
        "status": "success" if not errors else "partial_success",
        "message": f"{added_count} members added to group '{group.get('displayName')}'",
        "errors": errors if errors else None
    }


async def get_group_owners(group_id: str) -> dict[str, Any]:
    """
    Get owners of a group.
    
    Args:
        group_id: The group ID
    
    Returns:
        List of group owners
    """
    client = get_graph_client()
    
    group = await client.get(f"/groups/{group_id}?$select=displayName")
    
    response = await client.get(f"/groups/{group_id}/owners")
    owners = response.get("value", [])
    
    return {
        "group_name": group.get("displayName"),
        "group_id": group_id,
        "owner_count": len(owners),
        "owners": [
            {
                "id": o.get("id"),
                "displayName": o.get("displayName"),
                "userPrincipalName": o.get("userPrincipalName"),
            }
            for o in owners
        ]
    }


async def add_group_owner(group_id: str, owner_id: str) -> dict[str, Any]:
    """
    Add an owner to a group.
    
    Args:
        group_id: The group ID
        owner_id: The user ID to add as owner
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    group = await client.get(f"/groups/{group_id}?$select=displayName")
    owner = await client.get(f"/users/{owner_id}?$select=displayName")
    
    await client.post(
        f"/groups/{group_id}/owners/$ref",
        json={"@odata.id": f"https://graph.microsoft.com/v1.0/users/{owner_id}"}
    )
    
    return {
        "status": "success",
        "message": f"'{owner.get('displayName')}' added as owner of group '{group.get('displayName')}'"
    }


async def remove_group_owner(group_id: str, owner_id: str) -> dict[str, Any]:
    """
    Remove an owner from a group.
    
    Args:
        group_id: The group ID
        owner_id: The owner ID to remove
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    group = await client.get(f"/groups/{group_id}?$select=displayName")
    
    await client.delete(f"/groups/{group_id}/owners/{owner_id}/$ref")
    
    return {
        "status": "success",
        "message": f"Owner removed from group '{group.get('displayName')}'"
    }


async def check_group_membership(group_id: str, member_id: str) -> dict[str, Any]:
    """
    Check if a user/group is a member of a group (including nested membership).
    
    Args:
        group_id: The group ID to check
        member_id: The user or group ID to check membership for
    
    Returns:
        Membership status
    """
    client = get_graph_client()
    
    result = await client.post(
        f"/groups/{group_id}/checkMemberGroups",
        json={"groupIds": [group_id]}
    )
    
    # Alternative: check transitive membership
    try:
        await client.get(f"/groups/{group_id}/transitiveMembers/{member_id}")
        is_member = True
    except:
        is_member = False
    
    return {
        "group_id": group_id,
        "member_id": member_id,
        "is_member": is_member
    }


async def get_dynamic_group_membership_rule_validation(rule: str) -> dict[str, Any]:
    """
    Validate a dynamic group membership rule.
    
    Args:
        rule: The membership rule to validate
    
    Returns:
        Validation result
    """
    client = get_graph_client()
    
    # Use beta endpoint for rule validation
    try:
        result = await client.post(
            "/groups/validateProperties",
            json={
                "membershipRule": rule
            },
            use_beta=True
        )
        
        return {
            "status": "valid",
            "rule": rule,
            "message": "Membership rule is valid"
        }
    except Exception as e:
        return {
            "status": "invalid",
            "rule": rule,
            "error": str(e)
        }

