"""
Tenant Administration Tools
Organization settings, service health, subscriptions, and administrative operations.
"""

from typing import Any
from ..graph_client import get_graph_client


# ============== ORGANIZATION SETTINGS ==============

async def get_organization_info() -> dict[str, Any]:
    """
    Get organization/tenant information.
    
    Returns:
        Organization details
    """
    client = get_graph_client()
    
    org = await client.get("/organization")
    org_info = org.get("value", [{}])[0]
    
    return {
        "id": org_info.get("id"),
        "displayName": org_info.get("displayName"),
        "tenantType": org_info.get("tenantType"),
        "verifiedDomains": org_info.get("verifiedDomains"),
        "technicalNotificationMails": org_info.get("technicalNotificationMails"),
        "securityComplianceNotificationMails": org_info.get("securityComplianceNotificationMails"),
        "privacyProfile": org_info.get("privacyProfile"),
        "assignedPlans": len(org_info.get("assignedPlans", [])),
        "provisionedPlans": len(org_info.get("provisionedPlans", [])),
        "createdDateTime": org_info.get("createdDateTime"),
    }


async def get_tenant_domains() -> dict[str, Any]:
    """
    Get all domains associated with the tenant.
    
    Returns:
        List of domains with verification status
    """
    client = get_graph_client()
    
    response = await client.get("/domains")
    domains = response.get("value", [])
    
    return {
        "count": len(domains),
        "domains": [
            {
                "id": d.get("id"),
                "authenticationType": d.get("authenticationType"),
                "isAdminManaged": d.get("isAdminManaged"),
                "isDefault": d.get("isDefault"),
                "isInitial": d.get("isInitial"),
                "isRoot": d.get("isRoot"),
                "isVerified": d.get("isVerified"),
                "supportedServices": d.get("supportedServices"),
            }
            for d in domains
        ]
    }


async def get_organizational_branding() -> dict[str, Any]:
    """
    Get organizational branding settings.
    
    Returns:
        Branding configuration
    """
    client = get_graph_client()
    
    try:
        branding = await client.get("/organization/{organization-id}/branding")
        return {
            "backgroundColor": branding.get("backgroundColor"),
            "signInPageText": branding.get("signInPageText"),
            "usernameHintText": branding.get("usernameHintText"),
            "bannerLogoUrl": branding.get("bannerLogoRelativeUrl"),
            "backgroundImageUrl": branding.get("backgroundImageRelativeUrl"),
        }
    except:
        return {
            "status": "not_configured",
            "message": "Organizational branding is not configured"
        }


# ============== SERVICE HEALTH ==============

async def get_service_health() -> dict[str, Any]:
    """
    Get Microsoft 365 service health status.
    
    Returns:
        Current health status of M365 services
    """
    client = get_graph_client()
    
    response = await client.get("/admin/serviceAnnouncement/healthOverviews")
    services = response.get("value", [])
    
    healthy = sum(1 for s in services if s.get("status") == "serviceOperational")
    
    return {
        "summary": {
            "total_services": len(services),
            "healthy": healthy,
            "issues": len(services) - healthy,
        },
        "services": [
            {
                "id": s.get("id"),
                "service": s.get("service"),
                "status": s.get("status"),
            }
            for s in services
        ]
    }


async def get_service_issues(service_name: str = None, top: int = 50) -> dict[str, Any]:
    """
    Get current and recent service issues.
    
    Args:
        service_name: Filter by specific service (e.g., "Microsoft Intune")
        top: Maximum number of issues to return
    
    Returns:
        List of service issues
    """
    client = get_graph_client()
    
    endpoint = f"/admin/serviceAnnouncement/issues?$top={top}"
    if service_name:
        endpoint += f"&$filter=service eq '{service_name}'"
    
    response = await client.get(endpoint)
    issues = response.get("value", [])
    
    return {
        "count": len(issues),
        "issues": [
            {
                "id": i.get("id"),
                "service": i.get("service"),
                "title": i.get("title"),
                "impactDescription": i.get("impactDescription"),
                "classification": i.get("classification"),
                "origin": i.get("origin"),
                "status": i.get("status"),
                "startDateTime": i.get("startDateTime"),
                "endDateTime": i.get("endDateTime"),
                "lastModifiedDateTime": i.get("lastModifiedDateTime"),
            }
            for i in issues
        ]
    }


async def get_service_messages(top: int = 50, include_archived: bool = False) -> dict[str, Any]:
    """
    Get service announcements and message center posts.
    
    Args:
        top: Maximum number of messages to return
        include_archived: Include archived messages
    
    Returns:
        List of service messages
    """
    client = get_graph_client()
    
    endpoint = f"/admin/serviceAnnouncement/messages?$top={top}&$orderby=startDateTime desc"
    
    response = await client.get(endpoint)
    messages = response.get("value", [])
    
    return {
        "count": len(messages),
        "messages": [
            {
                "id": m.get("id"),
                "title": m.get("title"),
                "services": m.get("services"),
                "category": m.get("category"),
                "severity": m.get("severity"),
                "startDateTime": m.get("startDateTime"),
                "endDateTime": m.get("endDateTime"),
                "actionRequiredByDateTime": m.get("actionRequiredByDateTime"),
                "isMajorChange": m.get("isMajorChange"),
                "tags": m.get("tags"),
            }
            for m in messages
        ]
    }


# ============== DIRECTORY ROLES ==============

async def list_directory_roles() -> dict[str, Any]:
    """
    List all active directory roles.
    
    Returns:
        List of directory roles
    """
    client = get_graph_client()
    
    response = await client.get("/directoryRoles")
    roles = response.get("value", [])
    
    return {
        "count": len(roles),
        "roles": [
            {
                "id": r.get("id"),
                "displayName": r.get("displayName"),
                "description": r.get("description"),
                "roleTemplateId": r.get("roleTemplateId"),
            }
            for r in roles
        ]
    }


async def list_directory_role_templates() -> dict[str, Any]:
    """
    List all available directory role templates.
    
    Returns:
        List of role templates
    """
    client = get_graph_client()
    
    response = await client.get("/directoryRoleTemplates")
    templates = response.get("value", [])
    
    return {
        "count": len(templates),
        "templates": [
            {
                "id": t.get("id"),
                "displayName": t.get("displayName"),
                "description": t.get("description"),
            }
            for t in templates
        ]
    }


async def get_directory_role_members(role_id: str) -> dict[str, Any]:
    """
    Get members of a specific directory role.
    
    Args:
        role_id: The directory role ID
    
    Returns:
        List of role members
    """
    client = get_graph_client()
    
    role = await client.get(f"/directoryRoles/{role_id}")
    
    members = await client.get(f"/directoryRoles/{role_id}/members")
    member_list = members.get("value", [])
    
    return {
        "role": {
            "displayName": role.get("displayName"),
            "description": role.get("description"),
        },
        "member_count": len(member_list),
        "members": [
            {
                "id": m.get("id"),
                "displayName": m.get("displayName"),
                "userPrincipalName": m.get("userPrincipalName"),
                "type": m.get("@odata.type", "").replace("#microsoft.graph.", ""),
            }
            for m in member_list
        ]
    }


async def get_global_admins() -> dict[str, Any]:
    """
    Get all Global Administrator role members.
    
    Returns:
        List of global administrators
    """
    client = get_graph_client()
    
    # Get the Global Administrator role
    roles = await client.get("/directoryRoles?$filter=displayName eq 'Global Administrator'")
    role_list = roles.get("value", [])
    
    if not role_list:
        return {"count": 0, "members": [], "note": "Global Administrator role not found or not activated"}
    
    role = role_list[0]
    members = await client.get(f"/directoryRoles/{role['id']}/members")
    member_list = members.get("value", [])
    
    return {
        "count": len(member_list),
        "members": [
            {
                "id": m.get("id"),
                "displayName": m.get("displayName"),
                "userPrincipalName": m.get("userPrincipalName"),
            }
            for m in member_list
        ]
    }


async def add_directory_role_member(role_id: str, user_id: str) -> dict[str, Any]:
    """
    Add a user to a directory role.
    
    Args:
        role_id: The directory role ID
        user_id: The user ID to add
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    role = await client.get(f"/directoryRoles/{role_id}?$select=displayName")
    user = await client.get(f"/users/{user_id}?$select=displayName")
    
    await client.post(
        f"/directoryRoles/{role_id}/members/$ref",
        json={"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"}
    )
    
    return {
        "status": "success",
        "message": f"User '{user.get('displayName')}' added to role '{role.get('displayName')}'"
    }


async def remove_directory_role_member(role_id: str, user_id: str) -> dict[str, Any]:
    """
    Remove a user from a directory role.
    
    Args:
        role_id: The directory role ID
        user_id: The user ID to remove
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    role = await client.get(f"/directoryRoles/{role_id}?$select=displayName")
    
    await client.delete(f"/directoryRoles/{role_id}/members/{user_id}/$ref")
    
    return {
        "status": "success",
        "message": f"User removed from role '{role.get('displayName')}'"
    }


# ============== SUBSCRIPTIONS ==============

async def get_subscriptions() -> dict[str, Any]:
    """
    Get all subscribed SKUs (licenses) for the tenant.
    
    Returns:
        List of subscriptions with availability
    """
    client = get_graph_client()
    
    response = await client.get("/subscribedSkus")
    skus = response.get("value", [])
    
    return {
        "count": len(skus),
        "subscriptions": [
            {
                "skuId": s.get("skuId"),
                "skuPartNumber": s.get("skuPartNumber"),
                "capabilityStatus": s.get("capabilityStatus"),
                "prepaidUnits": {
                    "enabled": s.get("prepaidUnits", {}).get("enabled", 0),
                    "suspended": s.get("prepaidUnits", {}).get("suspended", 0),
                    "warning": s.get("prepaidUnits", {}).get("warning", 0),
                },
                "consumedUnits": s.get("consumedUnits"),
                "availableUnits": s.get("prepaidUnits", {}).get("enabled", 0) - s.get("consumedUnits", 0),
                "servicePlans": len(s.get("servicePlans", [])),
            }
            for s in skus
        ]
    }


async def get_subscription_details(sku_id: str) -> dict[str, Any]:
    """
    Get detailed information about a specific subscription.
    
    Args:
        sku_id: The SKU ID
    
    Returns:
        Subscription details including service plans
    """
    client = get_graph_client()
    
    response = await client.get(f"/subscribedSkus/{sku_id}")
    
    return {
        "skuId": response.get("skuId"),
        "skuPartNumber": response.get("skuPartNumber"),
        "capabilityStatus": response.get("capabilityStatus"),
        "prepaidUnits": response.get("prepaidUnits"),
        "consumedUnits": response.get("consumedUnits"),
        "servicePlans": [
            {
                "servicePlanId": sp.get("servicePlanId"),
                "servicePlanName": sp.get("servicePlanName"),
                "provisioningStatus": sp.get("provisioningStatus"),
                "appliesTo": sp.get("appliesTo"),
            }
            for sp in response.get("servicePlans", [])
        ]
    }


# ============== ADMINISTRATIVE UNITS ==============

async def list_administrative_units() -> dict[str, Any]:
    """
    List all administrative units.
    
    Returns:
        List of administrative units
    """
    client = get_graph_client()
    
    response = await client.get("/directory/administrativeUnits")
    aus = response.get("value", [])
    
    return {
        "count": len(aus),
        "administrative_units": [
            {
                "id": au.get("id"),
                "displayName": au.get("displayName"),
                "description": au.get("description"),
                "visibility": au.get("visibility"),
            }
            for au in aus
        ]
    }


async def get_administrative_unit_members(au_id: str) -> dict[str, Any]:
    """
    Get members of an administrative unit.
    
    Args:
        au_id: The administrative unit ID
    
    Returns:
        List of members
    """
    client = get_graph_client()
    
    au = await client.get(f"/directory/administrativeUnits/{au_id}")
    
    members = await client.get(f"/directory/administrativeUnits/{au_id}/members")
    member_list = members.get("value", [])
    
    return {
        "administrative_unit": {
            "displayName": au.get("displayName"),
            "description": au.get("description"),
        },
        "member_count": len(member_list),
        "members": [
            {
                "id": m.get("id"),
                "displayName": m.get("displayName"),
                "type": m.get("@odata.type", "").replace("#microsoft.graph.", ""),
            }
            for m in member_list
        ]
    }


# ============== APP REGISTRATIONS ==============

async def list_app_registrations(top: int = 50) -> dict[str, Any]:
    """
    List all app registrations in the tenant.
    
    Args:
        top: Maximum number of apps to return
    
    Returns:
        List of app registrations
    """
    client = get_graph_client()
    
    response = await client.get(f"/applications?$top={top}")
    apps = response.get("value", [])
    
    return {
        "count": len(apps),
        "applications": [
            {
                "id": a.get("id"),
                "appId": a.get("appId"),
                "displayName": a.get("displayName"),
                "createdDateTime": a.get("createdDateTime"),
                "signInAudience": a.get("signInAudience"),
                "publisherDomain": a.get("publisherDomain"),
            }
            for a in apps
        ]
    }


async def get_app_registration(app_id: str) -> dict[str, Any]:
    """
    Get details of a specific app registration.
    
    Args:
        app_id: The application ID (object ID, not client ID)
    
    Returns:
        App registration details
    """
    client = get_graph_client()
    
    app = await client.get(f"/applications/{app_id}")
    
    return {
        "id": app.get("id"),
        "appId": app.get("appId"),
        "displayName": app.get("displayName"),
        "createdDateTime": app.get("createdDateTime"),
        "signInAudience": app.get("signInAudience"),
        "publisherDomain": app.get("publisherDomain"),
        "identifierUris": app.get("identifierUris"),
        "web": app.get("web"),
        "api": app.get("api"),
        "requiredResourceAccess": app.get("requiredResourceAccess"),
        "passwordCredentials": [
            {
                "displayName": pc.get("displayName"),
                "endDateTime": pc.get("endDateTime"),
                "hint": pc.get("hint"),
            }
            for pc in app.get("passwordCredentials", [])
        ]
    }


async def list_service_principals(top: int = 50, filter_query: str = "") -> dict[str, Any]:
    """
    List service principals (enterprise apps) in the tenant.
    
    Args:
        top: Maximum number to return
        filter_query: OData filter
    
    Returns:
        List of service principals
    """
    client = get_graph_client()
    
    endpoint = f"/servicePrincipals?$top={top}"
    if filter_query:
        endpoint += f"&$filter={filter_query}"
    
    response = await client.get(endpoint)
    sps = response.get("value", [])
    
    return {
        "count": len(sps),
        "service_principals": [
            {
                "id": sp.get("id"),
                "appId": sp.get("appId"),
                "displayName": sp.get("displayName"),
                "servicePrincipalType": sp.get("servicePrincipalType"),
                "accountEnabled": sp.get("accountEnabled"),
            }
            for sp in sps
        ]
    }


# ============== SECURITY DEFAULTS ==============

async def get_security_defaults_status() -> dict[str, Any]:
    """
    Get the status of security defaults for the tenant.
    
    Returns:
        Security defaults configuration
    """
    client = get_graph_client()
    
    try:
        policy = await client.get("/policies/identitySecurityDefaultsEnforcementPolicy")
        return {
            "isEnabled": policy.get("isEnabled"),
            "displayName": policy.get("displayName"),
            "description": policy.get("description"),
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Could not retrieve security defaults: {str(e)}"
        }


async def set_security_defaults(enabled: bool, confirm: bool = False) -> dict[str, Any]:
    """
    Enable or disable security defaults.
    
    Args:
        enabled: Whether to enable security defaults
        confirm: Must be True to execute
    
    Returns:
        Status of the operation
    """
    if not confirm:
        action = "enable" if enabled else "disable"
        return {
            "status": "confirmation_required",
            "message": f"⚠️ This will {action} security defaults for the tenant! Set confirm=True to proceed."
        }
    
    client = get_graph_client()
    
    await client.patch(
        "/policies/identitySecurityDefaultsEnforcementPolicy",
        json={"isEnabled": enabled}
    )
    
    status = "enabled" if enabled else "disabled"
    return {
        "status": "success",
        "message": f"Security defaults {status}"
    }

