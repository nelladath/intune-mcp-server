"""
Conditional Access Policy Management Tools
Manage and monitor Conditional Access policies in Entra ID.
"""

from typing import Any
from ..graph_client import get_graph_client


async def list_conditional_access_policies(include_disabled: bool = True) -> dict[str, Any]:
    """
    List all Conditional Access policies.
    
    Args:
        include_disabled: Include disabled policies (default True)
    
    Returns:
        List of CA policies with their details
    """
    client = get_graph_client()
    
    response = await client.get("/identity/conditionalAccess/policies")
    policies = response.get("value", [])
    
    if not include_disabled:
        policies = [p for p in policies if p.get("state") == "enabled"]
    
    return {
        "count": len(policies),
        "policies": [
            {
                "id": p.get("id"),
                "displayName": p.get("displayName"),
                "state": p.get("state"),
                "createdDateTime": p.get("createdDateTime"),
                "modifiedDateTime": p.get("modifiedDateTime"),
                "conditions_summary": {
                    "users": _summarize_users(p.get("conditions", {}).get("users", {})),
                    "applications": _summarize_apps(p.get("conditions", {}).get("applications", {})),
                    "platforms": p.get("conditions", {}).get("platforms"),
                    "locations": p.get("conditions", {}).get("locations"),
                },
                "grant_controls": p.get("grantControls"),
                "session_controls": p.get("sessionControls"),
            }
            for p in policies
        ]
    }


def _summarize_users(users: dict) -> dict:
    """Summarize user conditions."""
    return {
        "include_users": users.get("includeUsers", []),
        "exclude_users": users.get("excludeUsers", []),
        "include_groups": users.get("includeGroups", []),
        "exclude_groups": users.get("excludeGroups", []),
        "include_roles": users.get("includeRoles", []),
    }


def _summarize_apps(apps: dict) -> dict:
    """Summarize application conditions."""
    return {
        "include_applications": apps.get("includeApplications", []),
        "exclude_applications": apps.get("excludeApplications", []),
        "include_user_actions": apps.get("includeUserActions", []),
    }


async def get_conditional_access_policy(policy_id: str) -> dict[str, Any]:
    """
    Get detailed information about a specific Conditional Access policy.
    
    Args:
        policy_id: The policy ID
    
    Returns:
        Complete policy configuration
    """
    client = get_graph_client()
    
    policy = await client.get(f"/identity/conditionalAccess/policies/{policy_id}")
    
    return {
        "id": policy.get("id"),
        "displayName": policy.get("displayName"),
        "state": policy.get("state"),
        "createdDateTime": policy.get("createdDateTime"),
        "modifiedDateTime": policy.get("modifiedDateTime"),
        "conditions": policy.get("conditions"),
        "grantControls": policy.get("grantControls"),
        "sessionControls": policy.get("sessionControls"),
    }


async def create_conditional_access_policy(
    display_name: str,
    state: str = "disabled",
    include_users: list = None,
    exclude_users: list = None,
    include_groups: list = None,
    exclude_groups: list = None,
    include_applications: list = None,
    exclude_applications: list = None,
    client_app_types: list = None,
    grant_controls: dict = None,
    conditions_platforms: dict = None,
    conditions_locations: dict = None
) -> dict[str, Any]:
    """
    Create a new Conditional Access policy.
    
    Args:
        display_name: Policy name
        state: "enabled", "disabled", or "enabledForReportingButNotEnforced"
        include_users: List of user IDs or "All"
        exclude_users: List of user IDs to exclude
        include_groups: List of group IDs
        exclude_groups: List of group IDs to exclude
        include_applications: List of app IDs or "All"
        exclude_applications: List of app IDs to exclude
        client_app_types: List like ["browser", "mobileAppsAndDesktopClients"]
        grant_controls: Grant control settings
        conditions_platforms: Platform conditions
        conditions_locations: Location conditions
    
    Returns:
        Created policy details
    """
    client = get_graph_client()
    
    policy_data = {
        "displayName": display_name,
        "state": state,
        "conditions": {
            "users": {
                "includeUsers": include_users or [],
                "excludeUsers": exclude_users or [],
                "includeGroups": include_groups or [],
                "excludeGroups": exclude_groups or [],
            },
            "applications": {
                "includeApplications": include_applications or ["All"],
                "excludeApplications": exclude_applications or [],
            },
            "clientAppTypes": client_app_types or ["all"],
        }
    }
    
    if conditions_platforms:
        policy_data["conditions"]["platforms"] = conditions_platforms
    
    if conditions_locations:
        policy_data["conditions"]["locations"] = conditions_locations
    
    if grant_controls:
        policy_data["grantControls"] = grant_controls
    else:
        # Default: require MFA
        policy_data["grantControls"] = {
            "operator": "OR",
            "builtInControls": ["mfa"]
        }
    
    result = await client.post("/identity/conditionalAccess/policies", json=policy_data)
    
    return {
        "status": "success",
        "message": f"Conditional Access policy '{display_name}' created",
        "policy": {
            "id": result.get("id"),
            "displayName": result.get("displayName"),
            "state": result.get("state"),
        }
    }


async def update_conditional_access_policy(
    policy_id: str,
    display_name: str = None,
    state: str = None,
    conditions: dict = None,
    grant_controls: dict = None,
    session_controls: dict = None
) -> dict[str, Any]:
    """
    Update a Conditional Access policy.
    
    Args:
        policy_id: The policy ID
        display_name: New policy name
        state: New state
        conditions: New conditions
        grant_controls: New grant controls
        session_controls: New session controls
    
    Returns:
        Update status
    """
    client = get_graph_client()
    
    update_data = {}
    if display_name is not None:
        update_data["displayName"] = display_name
    if state is not None:
        update_data["state"] = state
    if conditions is not None:
        update_data["conditions"] = conditions
    if grant_controls is not None:
        update_data["grantControls"] = grant_controls
    if session_controls is not None:
        update_data["sessionControls"] = session_controls
    
    if not update_data:
        return {"status": "error", "message": "No fields provided for update"}
    
    policy = await client.get(f"/identity/conditionalAccess/policies/{policy_id}?$select=displayName")
    
    await client.patch(f"/identity/conditionalAccess/policies/{policy_id}", json=update_data)
    
    return {
        "status": "success",
        "message": f"Policy '{policy.get('displayName')}' updated",
        "updated_fields": list(update_data.keys())
    }


async def enable_conditional_access_policy(policy_id: str) -> dict[str, Any]:
    """
    Enable a Conditional Access policy.
    
    Args:
        policy_id: The policy ID
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    policy = await client.get(f"/identity/conditionalAccess/policies/{policy_id}?$select=displayName")
    
    await client.patch(
        f"/identity/conditionalAccess/policies/{policy_id}",
        json={"state": "enabled"}
    )
    
    return {
        "status": "success",
        "message": f"Policy '{policy.get('displayName')}' enabled"
    }


async def disable_conditional_access_policy(policy_id: str) -> dict[str, Any]:
    """
    Disable a Conditional Access policy.
    
    Args:
        policy_id: The policy ID
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    policy = await client.get(f"/identity/conditionalAccess/policies/{policy_id}?$select=displayName")
    
    await client.patch(
        f"/identity/conditionalAccess/policies/{policy_id}",
        json={"state": "disabled"}
    )
    
    return {
        "status": "success",
        "message": f"Policy '{policy.get('displayName')}' disabled"
    }


async def set_policy_report_only(policy_id: str) -> dict[str, Any]:
    """
    Set a Conditional Access policy to report-only mode.
    
    Args:
        policy_id: The policy ID
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    policy = await client.get(f"/identity/conditionalAccess/policies/{policy_id}?$select=displayName")
    
    await client.patch(
        f"/identity/conditionalAccess/policies/{policy_id}",
        json={"state": "enabledForReportingButNotEnforced"}
    )
    
    return {
        "status": "success",
        "message": f"Policy '{policy.get('displayName')}' set to report-only mode"
    }


async def delete_conditional_access_policy(policy_id: str, confirm: bool = False) -> dict[str, Any]:
    """
    Delete a Conditional Access policy.
    
    Args:
        policy_id: The policy ID
        confirm: Must be True to execute deletion
    
    Returns:
        Deletion status
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "⚠️ DELETE will permanently remove the CA policy! Set confirm=True to proceed."
        }
    
    client = get_graph_client()
    
    policy = await client.get(f"/identity/conditionalAccess/policies/{policy_id}?$select=displayName")
    
    await client.delete(f"/identity/conditionalAccess/policies/{policy_id}")
    
    return {
        "status": "success",
        "message": f"Policy '{policy.get('displayName')}' deleted"
    }


async def list_named_locations() -> dict[str, Any]:
    """
    List all named locations used in Conditional Access.
    
    Returns:
        List of named locations
    """
    client = get_graph_client()
    
    response = await client.get("/identity/conditionalAccess/namedLocations")
    locations = response.get("value", [])
    
    return {
        "count": len(locations),
        "locations": [
            {
                "id": loc.get("id"),
                "displayName": loc.get("displayName"),
                "type": loc.get("@odata.type", "").replace("#microsoft.graph.", ""),
                "createdDateTime": loc.get("createdDateTime"),
                "modifiedDateTime": loc.get("modifiedDateTime"),
                "isTrusted": loc.get("isTrusted"),
                # For IP locations
                "ipRanges": loc.get("ipRanges"),
                # For country locations
                "countriesAndRegions": loc.get("countriesAndRegions"),
                "includeUnknownCountriesAndRegions": loc.get("includeUnknownCountriesAndRegions"),
            }
            for loc in locations
        ]
    }


async def create_ip_named_location(
    display_name: str,
    ip_ranges: list,
    is_trusted: bool = False
) -> dict[str, Any]:
    """
    Create a named location based on IP ranges.
    
    Args:
        display_name: Location name
        ip_ranges: List of IP ranges (e.g., ["10.0.0.0/8", "192.168.1.0/24"])
        is_trusted: Whether this is a trusted location
    
    Returns:
        Created location details
    """
    client = get_graph_client()
    
    location_data = {
        "@odata.type": "#microsoft.graph.ipNamedLocation",
        "displayName": display_name,
        "isTrusted": is_trusted,
        "ipRanges": [
            {"@odata.type": "#microsoft.graph.iPv4CidrRange", "cidrAddress": ip}
            if "." in ip else
            {"@odata.type": "#microsoft.graph.iPv6CidrRange", "cidrAddress": ip}
            for ip in ip_ranges
        ]
    }
    
    result = await client.post("/identity/conditionalAccess/namedLocations", json=location_data)
    
    return {
        "status": "success",
        "message": f"IP named location '{display_name}' created",
        "location": {
            "id": result.get("id"),
            "displayName": result.get("displayName"),
        }
    }


async def create_country_named_location(
    display_name: str,
    countries: list,
    include_unknown: bool = False
) -> dict[str, Any]:
    """
    Create a named location based on countries/regions.
    
    Args:
        display_name: Location name
        countries: List of country codes (e.g., ["US", "CA", "GB"])
        include_unknown: Include unknown countries/regions
    
    Returns:
        Created location details
    """
    client = get_graph_client()
    
    location_data = {
        "@odata.type": "#microsoft.graph.countryNamedLocation",
        "displayName": display_name,
        "countriesAndRegions": countries,
        "includeUnknownCountriesAndRegions": include_unknown
    }
    
    result = await client.post("/identity/conditionalAccess/namedLocations", json=location_data)
    
    return {
        "status": "success",
        "message": f"Country named location '{display_name}' created",
        "location": {
            "id": result.get("id"),
            "displayName": result.get("displayName"),
        }
    }


async def delete_named_location(location_id: str, confirm: bool = False) -> dict[str, Any]:
    """
    Delete a named location.
    
    Args:
        location_id: The location ID
        confirm: Must be True to execute deletion
    
    Returns:
        Deletion status
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "⚠️ DELETE will remove the named location! Set confirm=True to proceed."
        }
    
    client = get_graph_client()
    
    location = await client.get(f"/identity/conditionalAccess/namedLocations/{location_id}")
    
    await client.delete(f"/identity/conditionalAccess/namedLocations/{location_id}")
    
    return {
        "status": "success",
        "message": f"Named location '{location.get('displayName')}' deleted"
    }


async def get_conditional_access_policy_coverage() -> dict[str, Any]:
    """
    Analyze Conditional Access policy coverage to identify gaps.
    
    Returns:
        Analysis of CA policy coverage
    """
    client = get_graph_client()
    
    policies = await client.get("/identity/conditionalAccess/policies")
    policy_list = policies.get("value", [])
    
    analysis = {
        "total_policies": len(policy_list),
        "enabled_policies": 0,
        "disabled_policies": 0,
        "report_only_policies": 0,
        "policies_requiring_mfa": 0,
        "policies_blocking_access": 0,
        "policies_targeting_all_users": 0,
        "policies_targeting_all_apps": 0,
    }
    
    for policy in policy_list:
        state = policy.get("state")
        if state == "enabled":
            analysis["enabled_policies"] += 1
        elif state == "disabled":
            analysis["disabled_policies"] += 1
        else:
            analysis["report_only_policies"] += 1
        
        # Check grant controls
        grant_controls = policy.get("grantControls", {})
        built_in = grant_controls.get("builtInControls", [])
        if "mfa" in built_in:
            analysis["policies_requiring_mfa"] += 1
        if "block" in built_in:
            analysis["policies_blocking_access"] += 1
        
        # Check user scope
        users = policy.get("conditions", {}).get("users", {})
        if "All" in users.get("includeUsers", []):
            analysis["policies_targeting_all_users"] += 1
        
        # Check app scope
        apps = policy.get("conditions", {}).get("applications", {})
        if "All" in apps.get("includeApplications", []):
            analysis["policies_targeting_all_apps"] += 1
    
    return analysis

