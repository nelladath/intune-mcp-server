"""
App Registration & Enterprise Application (Service Principal) Tools
Comprehensive management of Entra ID applications including credentials, permissions, and enterprise apps.
"""

from typing import Any
from datetime import datetime, timezone
from ..graph_client import get_graph_client


# Permission ID to Name mappings for common Microsoft Graph permissions
GRAPH_PERMISSION_NAMES = {
    # Delegated permissions
    "e1fe6dd8-ba31-4d61-89e7-88639da4683d": "User.Read",
    "14dad69e-099b-42c9-810b-d002981feec1": "profile",
    "37f7f235-527c-4136-accd-4a02d197296e": "openid",
    "7427e0e9-2fba-42fe-b0c0-848c9e6a8182": "offline_access",
    "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0": "email",
    # Application permissions
    "df021288-bdef-4463-88db-98f22de89214": "User.Read.All",
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
    "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30": "Application.Read.All",
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
    "7ab1d382-f21e-4acd-a863-ba3e13f7da61": "Directory.Read.All",
    "62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
    "5b567255-7703-4780-807c-7be8301ae99b": "Group.Read.All",
    "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
    "243333ab-4d21-40cb-a475-36241daa0842": "DeviceManagementManagedDevices.ReadWrite.All",
    "2f51be20-0bb4-4fed-bf7b-db946066c75e": "DeviceManagementManagedDevices.Read.All",
    "78145de6-330d-4800-a6ce-494ff2d33d07": "DeviceManagementApps.ReadWrite.All",
    "7a6ee1e7-141e-4cec-ae74-d9db155731ff": "DeviceManagementApps.Read.All",
    "5ac13192-7ace-4fcf-b828-1a26f28068ee": "DeviceManagementConfiguration.ReadWrite.All",
    "dc377aa6-52d8-4e23-b271-2a7ae6a351ac": "DeviceManagementConfiguration.Read.All",
    "58ca0d9a-1575-47e1-a3cb-007ef2e4583b": "DeviceManagementRBAC.ReadWrite.All",
    "49f0cc30-024c-4f45-b9a6-79c64b29cd9d": "DeviceManagementRBAC.Read.All",
    "5b07b0dd-2377-4e44-a38d-703f09a0dc3c": "DeviceManagementServiceConfig.ReadWrite.All",
    "06a5fe6d-c49d-46a7-b082-56b1b14103c7": "DeviceManagementServiceConfig.Read.All",
}


def calculate_days_until_expiry(expiry_date_str: str) -> dict:
    """Calculate days until expiry and status."""
    if not expiry_date_str:
        return {"days": None, "status": "unknown"}
    
    try:
        expiry = datetime.fromisoformat(expiry_date_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        delta = expiry - now
        days = delta.days
        
        if days < 0:
            status = "expired"
        elif days <= 30:
            status = "critical"
        elif days <= 90:
            status = "warning"
        else:
            status = "healthy"
        
        return {"days": days, "status": status}
    except:
        return {"days": None, "status": "unknown"}


async def list_app_registrations_with_credentials(top: int = 50) -> dict[str, Any]:
    """
    List all app registrations with credential expiry information.
    
    Args:
        top: Maximum number of apps to return
    
    Returns:
        List of app registrations with secret/certificate expiry dates
    """
    client = get_graph_client()
    
    response = await client.get(
        f"/applications?$top={top}&$select=id,appId,displayName,createdDateTime,signInAudience,passwordCredentials,keyCredentials"
    )
    apps = response.get("value", [])
    
    app_list = []
    expiring_soon = []
    expired = []
    
    for app in apps:
        secrets = []
        for cred in app.get("passwordCredentials", []):
            expiry_info = calculate_days_until_expiry(cred.get("endDateTime"))
            secret_info = {
                "displayName": cred.get("displayName") or "Secret",
                "hint": cred.get("hint"),
                "startDateTime": cred.get("startDateTime"),
                "endDateTime": cred.get("endDateTime"),
                "daysUntilExpiry": expiry_info["days"],
                "status": expiry_info["status"]
            }
            secrets.append(secret_info)
            
            if expiry_info["status"] == "expired":
                expired.append({"app": app.get("displayName"), "credential": cred.get("displayName"), "expiry": cred.get("endDateTime")})
            elif expiry_info["status"] in ["critical", "warning"]:
                expiring_soon.append({"app": app.get("displayName"), "credential": cred.get("displayName"), "expiry": cred.get("endDateTime"), "days": expiry_info["days"]})
        
        certificates = []
        for cert in app.get("keyCredentials", []):
            expiry_info = calculate_days_until_expiry(cert.get("endDateTime"))
            cert_info = {
                "displayName": cert.get("displayName") or "Certificate",
                "type": cert.get("type"),
                "usage": cert.get("usage"),
                "startDateTime": cert.get("startDateTime"),
                "endDateTime": cert.get("endDateTime"),
                "daysUntilExpiry": expiry_info["days"],
                "status": expiry_info["status"]
            }
            certificates.append(cert_info)
            
            if expiry_info["status"] == "expired":
                expired.append({"app": app.get("displayName"), "credential": cert.get("displayName"), "expiry": cert.get("endDateTime")})
            elif expiry_info["status"] in ["critical", "warning"]:
                expiring_soon.append({"app": app.get("displayName"), "credential": cert.get("displayName"), "expiry": cert.get("endDateTime"), "days": expiry_info["days"]})
        
        app_list.append({
            "id": app.get("id"),
            "appId": app.get("appId"),
            "displayName": app.get("displayName"),
            "createdDateTime": app.get("createdDateTime"),
            "signInAudience": app.get("signInAudience"),
            "secretCount": len(secrets),
            "certificateCount": len(certificates),
            "secrets": secrets,
            "certificates": certificates
        })
    
    return {
        "count": len(app_list),
        "summary": {
            "total_apps": len(app_list),
            "expired_credentials": len(expired),
            "expiring_soon": len(expiring_soon)
        },
        "expired_credentials": expired,
        "expiring_soon": expiring_soon,
        "applications": app_list
    }


async def get_app_registration_details(app_id: str) -> dict[str, Any]:
    """
    Get comprehensive details of an app registration including permissions and credentials.
    
    Args:
        app_id: The application object ID or client ID
    
    Returns:
        Complete app registration details
    """
    client = get_graph_client()
    
    # Try to find by object ID first, then by appId
    try:
        app = await client.get(f"/applications/{app_id}")
    except:
        # Search by appId (client ID)
        response = await client.get(f"/applications?$filter=appId eq '{app_id}'")
        apps = response.get("value", [])
        if not apps:
            return {"error": f"Application not found: {app_id}"}
        app = apps[0]
    
    # Process password credentials (secrets)
    secrets = []
    for cred in app.get("passwordCredentials", []):
        expiry_info = calculate_days_until_expiry(cred.get("endDateTime"))
        secrets.append({
            "displayName": cred.get("displayName") or "Secret",
            "hint": cred.get("hint"),
            "startDateTime": cred.get("startDateTime"),
            "endDateTime": cred.get("endDateTime"),
            "daysUntilExpiry": expiry_info["days"],
            "status": expiry_info["status"]
        })
    
    # Process key credentials (certificates)
    certificates = []
    for cert in app.get("keyCredentials", []):
        expiry_info = calculate_days_until_expiry(cert.get("endDateTime"))
        certificates.append({
            "displayName": cert.get("displayName") or "Certificate",
            "type": cert.get("type"),
            "usage": cert.get("usage"),
            "thumbprint": cert.get("customKeyIdentifier"),
            "startDateTime": cert.get("startDateTime"),
            "endDateTime": cert.get("endDateTime"),
            "daysUntilExpiry": expiry_info["days"],
            "status": expiry_info["status"]
        })
    
    # Process API permissions
    api_permissions = []
    for resource in app.get("requiredResourceAccess", []):
        resource_app_id = resource.get("resourceAppId")
        
        # Try to get resource name
        resource_name = "Unknown Resource"
        if resource_app_id == "00000003-0000-0000-c000-000000000000":
            resource_name = "Microsoft Graph"
        
        permissions = []
        for perm in resource.get("resourceAccess", []):
            perm_id = perm.get("id")
            perm_type = perm.get("type")  # "Scope" = Delegated, "Role" = Application
            perm_name = GRAPH_PERMISSION_NAMES.get(perm_id, perm_id)
            
            permissions.append({
                "id": perm_id,
                "name": perm_name,
                "type": "Delegated" if perm_type == "Scope" else "Application"
            })
        
        api_permissions.append({
            "resourceAppId": resource_app_id,
            "resourceName": resource_name,
            "permissions": permissions
        })
    
    return {
        "id": app.get("id"),
        "appId": app.get("appId"),
        "displayName": app.get("displayName"),
        "createdDateTime": app.get("createdDateTime"),
        "signInAudience": app.get("signInAudience"),
        "publisherDomain": app.get("publisherDomain"),
        "identifierUris": app.get("identifierUris", []),
        "web": {
            "redirectUris": app.get("web", {}).get("redirectUris", []),
            "logoutUrl": app.get("web", {}).get("logoutUrl"),
            "implicitGrantSettings": app.get("web", {}).get("implicitGrantSettings")
        },
        "spa": {
            "redirectUris": app.get("spa", {}).get("redirectUris", [])
        },
        "publicClient": {
            "redirectUris": app.get("publicClient", {}).get("redirectUris", [])
        },
        "credentials": {
            "secretCount": len(secrets),
            "certificateCount": len(certificates),
            "secrets": secrets,
            "certificates": certificates
        },
        "apiPermissions": api_permissions,
        "appRoles": app.get("appRoles", []),
        "oauth2Permissions": app.get("api", {}).get("oauth2PermissionScopes", [])
    }


async def search_app_registrations(search_term: str) -> dict[str, Any]:
    """
    Search for app registrations by name.
    
    Args:
        search_term: The search term
    
    Returns:
        Matching app registrations
    """
    client = get_graph_client()
    
    response = await client.get(
        f"/applications?$filter=startswith(displayName, '{search_term}')&$select=id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials&$top=50"
    )
    apps = response.get("value", [])
    
    return {
        "search_term": search_term,
        "count": len(apps),
        "applications": [
            {
                "id": a.get("id"),
                "appId": a.get("appId"),
                "displayName": a.get("displayName"),
                "createdDateTime": a.get("createdDateTime"),
                "secretCount": len(a.get("passwordCredentials", [])),
                "certificateCount": len(a.get("keyCredentials", []))
            }
            for a in apps
        ]
    }


# ============== ENTERPRISE APPLICATIONS (SERVICE PRINCIPALS) ==============

async def list_enterprise_apps(top: int = 50, app_type: str = None) -> dict[str, Any]:
    """
    List enterprise applications (service principals).
    
    Args:
        top: Maximum number to return
        app_type: Filter by type - "Application", "ManagedIdentity", "Legacy", or None for all
    
    Returns:
        List of enterprise applications
    """
    client = get_graph_client()
    
    endpoint = f"/servicePrincipals?$top={top}&$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,createdDateTime,tags"
    
    if app_type:
        endpoint += f"&$filter=servicePrincipalType eq '{app_type}'"
    
    response = await client.get(endpoint)
    sps = response.get("value", [])
    
    return {
        "count": len(sps),
        "enterprise_applications": [
            {
                "id": sp.get("id"),
                "appId": sp.get("appId"),
                "displayName": sp.get("displayName"),
                "servicePrincipalType": sp.get("servicePrincipalType"),
                "accountEnabled": sp.get("accountEnabled"),
                "createdDateTime": sp.get("createdDateTime"),
                "tags": sp.get("tags", [])
            }
            for sp in sps
        ]
    }


async def get_enterprise_app_details(sp_id: str) -> dict[str, Any]:
    """
    Get comprehensive details of an enterprise application including permissions and assignments.
    
    Args:
        sp_id: Service principal ID or app ID
    
    Returns:
        Complete enterprise app details
    """
    client = get_graph_client()
    
    # Try to find by ID first, then by appId
    try:
        sp = await client.get(f"/servicePrincipals/{sp_id}")
    except:
        response = await client.get(f"/servicePrincipals?$filter=appId eq '{sp_id}'")
        sps = response.get("value", [])
        if not sps:
            return {"error": f"Enterprise application not found: {sp_id}"}
        sp = sps[0]
    
    sp_object_id = sp.get("id")
    
    # Get app role assignments (who/what is assigned to this app)
    try:
        assignments_response = await client.get(f"/servicePrincipals/{sp_object_id}/appRoleAssignedTo")
        app_role_assignments = assignments_response.get("value", [])
    except:
        app_role_assignments = []
    
    # Get OAuth2 permission grants (delegated permissions granted)
    try:
        oauth_grants_response = await client.get(f"/servicePrincipals/{sp_object_id}/oauth2PermissionGrants")
        oauth_grants = oauth_grants_response.get("value", [])
    except:
        oauth_grants = []
    
    # Get owners
    try:
        owners_response = await client.get(f"/servicePrincipals/{sp_object_id}/owners")
        owners = owners_response.get("value", [])
    except:
        owners = []
    
    return {
        "id": sp.get("id"),
        "appId": sp.get("appId"),
        "displayName": sp.get("displayName"),
        "servicePrincipalType": sp.get("servicePrincipalType"),
        "accountEnabled": sp.get("accountEnabled"),
        "appOwnerOrganizationId": sp.get("appOwnerOrganizationId"),
        "createdDateTime": sp.get("createdDateTime"),
        "description": sp.get("description"),
        "homepage": sp.get("homepage"),
        "loginUrl": sp.get("loginUrl"),
        "logoutUrl": sp.get("logoutUrl"),
        "replyUrls": sp.get("replyUrls", []),
        "tags": sp.get("tags", []),
        "appRoles": sp.get("appRoles", []),
        "appRoleAssignments": [
            {
                "id": a.get("id"),
                "principalDisplayName": a.get("principalDisplayName"),
                "principalType": a.get("principalType"),
                "resourceDisplayName": a.get("resourceDisplayName"),
                "createdDateTime": a.get("createdDateTime")
            }
            for a in app_role_assignments
        ],
        "oauth2PermissionGrants": [
            {
                "id": g.get("id"),
                "clientId": g.get("clientId"),
                "consentType": g.get("consentType"),
                "principalId": g.get("principalId"),
                "resourceId": g.get("resourceId"),
                "scope": g.get("scope")
            }
            for g in oauth_grants
        ],
        "owners": [
            {
                "id": o.get("id"),
                "displayName": o.get("displayName"),
                "userPrincipalName": o.get("userPrincipalName")
            }
            for o in owners
        ]
    }


async def search_enterprise_apps(search_term: str) -> dict[str, Any]:
    """
    Search for enterprise applications by name.
    
    Args:
        search_term: The search term
    
    Returns:
        Matching enterprise applications
    """
    client = get_graph_client()
    
    response = await client.get(
        f"/servicePrincipals?$filter=startswith(displayName, '{search_term}')&$select=id,appId,displayName,servicePrincipalType,accountEnabled&$top=50"
    )
    sps = response.get("value", [])
    
    return {
        "search_term": search_term,
        "count": len(sps),
        "enterprise_applications": [
            {
                "id": sp.get("id"),
                "appId": sp.get("appId"),
                "displayName": sp.get("displayName"),
                "servicePrincipalType": sp.get("servicePrincipalType"),
                "accountEnabled": sp.get("accountEnabled")
            }
            for sp in sps
        ]
    }


async def get_app_permissions_granted(sp_id: str) -> dict[str, Any]:
    """
    Get all permissions granted to an enterprise application.
    
    Args:
        sp_id: Service principal ID
    
    Returns:
        All granted permissions (delegated and application)
    """
    client = get_graph_client()
    
    # Get the service principal
    try:
        sp = await client.get(f"/servicePrincipals/{sp_id}?$select=id,displayName,appId")
    except:
        response = await client.get(f"/servicePrincipals?$filter=appId eq '{sp_id}'")
        sps = response.get("value", [])
        if not sps:
            return {"error": f"Enterprise application not found: {sp_id}"}
        sp = sps[0]
    
    sp_object_id = sp.get("id")
    
    # Get application permissions (app roles assigned to this SP)
    app_roles = []
    try:
        roles_response = await client.get(f"/servicePrincipals/{sp_object_id}/appRoleAssignments")
        for role in roles_response.get("value", []):
            app_roles.append({
                "resourceDisplayName": role.get("resourceDisplayName"),
                "appRoleId": role.get("appRoleId"),
                "createdDateTime": role.get("createdDateTime")
            })
    except:
        pass
    
    # Get delegated permissions (OAuth2 permission grants)
    delegated = []
    try:
        grants_response = await client.get(f"/servicePrincipals/{sp_object_id}/oauth2PermissionGrants")
        for grant in grants_response.get("value", []):
            delegated.append({
                "consentType": grant.get("consentType"),  # "AllPrincipals" or "Principal"
                "scope": grant.get("scope"),
                "principalId": grant.get("principalId")
            })
    except:
        pass
    
    return {
        "servicePrincipal": {
            "id": sp.get("id"),
            "displayName": sp.get("displayName"),
            "appId": sp.get("appId")
        },
        "applicationPermissions": app_roles,
        "delegatedPermissions": delegated
    }


async def enable_enterprise_app(sp_id: str) -> dict[str, Any]:
    """
    Enable an enterprise application.
    
    Args:
        sp_id: Service principal ID
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    sp = await client.get(f"/servicePrincipals/{sp_id}?$select=displayName")
    
    await client.patch(f"/servicePrincipals/{sp_id}", json={"accountEnabled": True})
    
    return {
        "status": "success",
        "message": f"Enterprise application '{sp.get('displayName')}' has been enabled"
    }


async def disable_enterprise_app(sp_id: str) -> dict[str, Any]:
    """
    Disable an enterprise application.
    
    Args:
        sp_id: Service principal ID
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    sp = await client.get(f"/servicePrincipals/{sp_id}?$select=displayName")
    
    await client.patch(f"/servicePrincipals/{sp_id}", json={"accountEnabled": False})
    
    return {
        "status": "success",
        "message": f"Enterprise application '{sp.get('displayName')}' has been disabled"
    }


async def get_credentials_expiring_soon(days: int = 30) -> dict[str, Any]:
    """
    Get all app registrations with credentials expiring within specified days.
    
    Args:
        days: Number of days to look ahead (default 30)
    
    Returns:
        Apps with expiring credentials
    """
    client = get_graph_client()
    
    response = await client.get(
        "/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials"
    )
    apps = response.get("value", [])
    
    expiring = []
    expired = []
    
    for app in apps:
        app_name = app.get("displayName")
        app_id = app.get("appId")
        
        # Check secrets
        for cred in app.get("passwordCredentials", []):
            expiry_info = calculate_days_until_expiry(cred.get("endDateTime"))
            if expiry_info["days"] is not None:
                if expiry_info["days"] < 0:
                    expired.append({
                        "appName": app_name,
                        "appId": app_id,
                        "credentialType": "Secret",
                        "credentialName": cred.get("displayName"),
                        "expiry": cred.get("endDateTime"),
                        "daysExpired": abs(expiry_info["days"])
                    })
                elif expiry_info["days"] <= days:
                    expiring.append({
                        "appName": app_name,
                        "appId": app_id,
                        "credentialType": "Secret",
                        "credentialName": cred.get("displayName"),
                        "expiry": cred.get("endDateTime"),
                        "daysRemaining": expiry_info["days"]
                    })
        
        # Check certificates
        for cert in app.get("keyCredentials", []):
            expiry_info = calculate_days_until_expiry(cert.get("endDateTime"))
            if expiry_info["days"] is not None:
                if expiry_info["days"] < 0:
                    expired.append({
                        "appName": app_name,
                        "appId": app_id,
                        "credentialType": "Certificate",
                        "credentialName": cert.get("displayName"),
                        "expiry": cert.get("endDateTime"),
                        "daysExpired": abs(expiry_info["days"])
                    })
                elif expiry_info["days"] <= days:
                    expiring.append({
                        "appName": app_name,
                        "appId": app_id,
                        "credentialType": "Certificate",
                        "credentialName": cert.get("displayName"),
                        "expiry": cert.get("endDateTime"),
                        "daysRemaining": expiry_info["days"]
                    })
    
    # Sort by days remaining
    expiring.sort(key=lambda x: x["daysRemaining"])
    expired.sort(key=lambda x: x["daysExpired"], reverse=True)
    
    return {
        "lookAheadDays": days,
        "summary": {
            "expired": len(expired),
            "expiringSoon": len(expiring)
        },
        "expiredCredentials": expired,
        "expiringCredentials": expiring
    }


async def delete_app_registration(app_id: str, confirm: bool = False) -> dict[str, Any]:
    """
    Delete an app registration.
    
    Args:
        app_id: Application object ID
        confirm: Must be True to execute deletion
    
    Returns:
        Status of the operation
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "⚠️ This will permanently delete the app registration! Set confirm=True to proceed."
        }
    
    client = get_graph_client()
    
    # Get app name first
    app = await client.get(f"/applications/{app_id}?$select=displayName")
    app_name = app.get("displayName")
    
    await client.delete(f"/applications/{app_id}")
    
    return {
        "status": "success",
        "message": f"App registration '{app_name}' has been deleted"
    }

