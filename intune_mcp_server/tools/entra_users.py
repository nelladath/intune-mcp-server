"""
Entra ID (Azure AD) User Management Tools
Comprehensive user management including CRUD, passwords, licenses, and authentication.
"""

from typing import Any
from ..graph_client import get_graph_client


async def list_users(top: int = 50, filter_query: str = "", select_fields: str = "") -> dict[str, Any]:
    """
    List all users in the tenant.
    
    Args:
        top: Maximum number of users to return (default 50, max 999)
        filter_query: OData filter (e.g., "accountEnabled eq true")
        select_fields: Comma-separated fields to return
    
    Returns:
        List of users with their details
    """
    client = get_graph_client()
    
    endpoint = "/users"
    params = [f"$top={min(top, 999)}"]
    if filter_query:
        params.append(f"$filter={filter_query}")
    if select_fields:
        params.append(f"$select={select_fields}")
    else:
        params.append("$select=id,displayName,userPrincipalName,mail,jobTitle,department,accountEnabled,createdDateTime")
    
    endpoint += "?" + "&".join(params)
    
    response = await client.get(endpoint)
    users = response.get("value", [])
    
    return {
        "count": len(users),
        "users": users
    }


async def get_user_details(user_id: str) -> dict[str, Any]:
    """
    Get comprehensive details for a specific user.
    
    Args:
        user_id: The user ID or userPrincipalName
    
    Returns:
        Complete user information
    """
    client = get_graph_client()
    
    user = await client.get(f"/users/{user_id}?$select=id,displayName,userPrincipalName,mail,givenName,surname,jobTitle,department,officeLocation,companyName,employeeId,employeeType,mobilePhone,businessPhones,streetAddress,city,state,postalCode,country,accountEnabled,createdDateTime,lastPasswordChangeDateTime,assignedLicenses,assignedPlans")
    
    # Get manager
    try:
        manager = await client.get(f"/users/{user_id}/manager?$select=displayName,userPrincipalName")
        manager_info = {"displayName": manager.get("displayName"), "userPrincipalName": manager.get("userPrincipalName")}
    except:
        manager_info = None
    
    # Get direct reports count
    try:
        reports = await client.get(f"/users/{user_id}/directReports?$count=true&$top=1")
        direct_reports_count = len(reports.get("value", []))
    except:
        direct_reports_count = 0
    
    return {
        "basic_info": {
            "id": user.get("id"),
            "displayName": user.get("displayName"),
            "userPrincipalName": user.get("userPrincipalName"),
            "mail": user.get("mail"),
            "givenName": user.get("givenName"),
            "surname": user.get("surname"),
        },
        "work_info": {
            "jobTitle": user.get("jobTitle"),
            "department": user.get("department"),
            "companyName": user.get("companyName"),
            "officeLocation": user.get("officeLocation"),
            "employeeId": user.get("employeeId"),
            "employeeType": user.get("employeeType"),
        },
        "contact_info": {
            "mobilePhone": user.get("mobilePhone"),
            "businessPhones": user.get("businessPhones"),
            "streetAddress": user.get("streetAddress"),
            "city": user.get("city"),
            "state": user.get("state"),
            "postalCode": user.get("postalCode"),
            "country": user.get("country"),
        },
        "account_info": {
            "accountEnabled": user.get("accountEnabled"),
            "createdDateTime": user.get("createdDateTime"),
            "lastPasswordChangeDateTime": user.get("lastPasswordChangeDateTime"),
        },
        "manager": manager_info,
        "direct_reports_count": direct_reports_count,
        "license_count": len(user.get("assignedLicenses", [])),
    }


async def create_user(
    display_name: str,
    user_principal_name: str,
    mail_nickname: str,
    password: str,
    account_enabled: bool = True,
    force_change_password: bool = True,
    given_name: str = "",
    surname: str = "",
    job_title: str = "",
    department: str = "",
    office_location: str = "",
    mobile_phone: str = ""
) -> dict[str, Any]:
    """
    Create a new user in Entra ID.
    
    Args:
        display_name: User's display name
        user_principal_name: User's UPN (e.g., user@domain.com)
        mail_nickname: Mail alias (without domain)
        password: Initial password
        account_enabled: Whether account is enabled (default True)
        force_change_password: Force password change on first login (default True)
        given_name: First name
        surname: Last name
        job_title: Job title
        department: Department name
        office_location: Office location
        mobile_phone: Mobile phone number
    
    Returns:
        Created user details
    """
    client = get_graph_client()
    
    user_data = {
        "accountEnabled": account_enabled,
        "displayName": display_name,
        "mailNickname": mail_nickname,
        "userPrincipalName": user_principal_name,
        "passwordProfile": {
            "forceChangePasswordNextSignIn": force_change_password,
            "password": password
        }
    }
    
    # Add optional fields if provided
    if given_name:
        user_data["givenName"] = given_name
    if surname:
        user_data["surname"] = surname
    if job_title:
        user_data["jobTitle"] = job_title
    if department:
        user_data["department"] = department
    if office_location:
        user_data["officeLocation"] = office_location
    if mobile_phone:
        user_data["mobilePhone"] = mobile_phone
    
    result = await client.post("/users", json=user_data)
    
    return {
        "status": "success",
        "message": f"User '{display_name}' created successfully",
        "user": {
            "id": result.get("id"),
            "displayName": result.get("displayName"),
            "userPrincipalName": result.get("userPrincipalName"),
        }
    }


async def update_user(
    user_id: str,
    display_name: str = None,
    given_name: str = None,
    surname: str = None,
    job_title: str = None,
    department: str = None,
    office_location: str = None,
    mobile_phone: str = None,
    company_name: str = None,
    employee_id: str = None,
    street_address: str = None,
    city: str = None,
    state: str = None,
    postal_code: str = None,
    country: str = None
) -> dict[str, Any]:
    """
    Update user properties.
    
    Args:
        user_id: The user ID or userPrincipalName
        display_name: New display name
        given_name: First name
        surname: Last name
        job_title: Job title
        department: Department
        office_location: Office location
        mobile_phone: Mobile phone
        company_name: Company name
        employee_id: Employee ID
        street_address: Street address
        city: City
        state: State/Province
        postal_code: Postal/ZIP code
        country: Country
    
    Returns:
        Update status
    """
    client = get_graph_client()
    
    update_data = {}
    
    # Only add fields that were provided
    if display_name is not None:
        update_data["displayName"] = display_name
    if given_name is not None:
        update_data["givenName"] = given_name
    if surname is not None:
        update_data["surname"] = surname
    if job_title is not None:
        update_data["jobTitle"] = job_title
    if department is not None:
        update_data["department"] = department
    if office_location is not None:
        update_data["officeLocation"] = office_location
    if mobile_phone is not None:
        update_data["mobilePhone"] = mobile_phone
    if company_name is not None:
        update_data["companyName"] = company_name
    if employee_id is not None:
        update_data["employeeId"] = employee_id
    if street_address is not None:
        update_data["streetAddress"] = street_address
    if city is not None:
        update_data["city"] = city
    if state is not None:
        update_data["state"] = state
    if postal_code is not None:
        update_data["postalCode"] = postal_code
    if country is not None:
        update_data["country"] = country
    
    if not update_data:
        return {"status": "error", "message": "No fields provided for update"}
    
    # Get user name for confirmation
    user = await client.get(f"/users/{user_id}?$select=displayName")
    
    await client.patch(f"/users/{user_id}", json=update_data)
    
    return {
        "status": "success",
        "message": f"User '{user.get('displayName')}' updated successfully",
        "updated_fields": list(update_data.keys())
    }


async def delete_user(user_id: str, confirm: bool = False) -> dict[str, Any]:
    """
    Delete a user from Entra ID. User will be moved to deleted users (recoverable for 30 days).
    
    Args:
        user_id: The user ID or userPrincipalName
        confirm: Must be True to execute deletion
    
    Returns:
        Deletion status
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "⚠️ DELETE will remove the user! Set confirm=True to proceed.",
            "note": "User will be recoverable from deleted users for 30 days"
        }
    
    client = get_graph_client()
    
    # Get user info before deletion
    user = await client.get(f"/users/{user_id}?$select=displayName,userPrincipalName")
    
    await client.delete(f"/users/{user_id}")
    
    return {
        "status": "success",
        "message": f"User '{user.get('displayName')}' deleted",
        "user_principal_name": user.get("userPrincipalName"),
        "note": "User moved to deleted users, recoverable for 30 days"
    }


async def enable_user(user_id: str) -> dict[str, Any]:
    """
    Enable a user account.
    
    Args:
        user_id: The user ID or userPrincipalName
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    user = await client.get(f"/users/{user_id}?$select=displayName")
    
    await client.patch(f"/users/{user_id}", json={"accountEnabled": True})
    
    return {
        "status": "success",
        "message": f"User '{user.get('displayName')}' has been enabled"
    }


async def disable_user(user_id: str) -> dict[str, Any]:
    """
    Disable a user account (blocks sign-in).
    
    Args:
        user_id: The user ID or userPrincipalName
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    user = await client.get(f"/users/{user_id}?$select=displayName")
    
    await client.patch(f"/users/{user_id}", json={"accountEnabled": False})
    
    return {
        "status": "success",
        "message": f"User '{user.get('displayName')}' has been disabled (sign-in blocked)"
    }


async def reset_user_password(
    user_id: str,
    new_password: str,
    force_change_on_next_login: bool = True
) -> dict[str, Any]:
    """
    Reset a user's password.
    
    Args:
        user_id: The user ID or userPrincipalName
        new_password: The new password
        force_change_on_next_login: Whether to force password change (default True)
    
    Returns:
        Status of password reset
    """
    client = get_graph_client()
    
    user = await client.get(f"/users/{user_id}?$select=displayName")
    
    await client.patch(
        f"/users/{user_id}",
        json={
            "passwordProfile": {
                "forceChangePasswordNextSignIn": force_change_on_next_login,
                "password": new_password
            }
        }
    )
    
    return {
        "status": "success",
        "message": f"Password reset for user '{user.get('displayName')}'",
        "force_change_on_login": force_change_on_next_login
    }


async def revoke_user_sessions(user_id: str) -> dict[str, Any]:
    """
    Revoke all refresh tokens for a user (forces re-authentication).
    
    Args:
        user_id: The user ID or userPrincipalName
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    user = await client.get(f"/users/{user_id}?$select=displayName")
    
    await client.post(f"/users/{user_id}/revokeSignInSessions")
    
    return {
        "status": "success",
        "message": f"All sessions revoked for user '{user.get('displayName')}'",
        "note": "User will need to sign in again on all devices"
    }


async def get_user_sign_in_activity(user_id: str) -> dict[str, Any]:
    """
    Get sign-in activity information for a user.
    
    Args:
        user_id: The user ID or userPrincipalName
    
    Returns:
        Sign-in activity details
    """
    client = get_graph_client()
    
    # Need beta endpoint for sign-in activity
    user = await client.get(
        f"/users/{user_id}?$select=displayName,userPrincipalName,signInActivity",
        use_beta=True
    )
    
    sign_in = user.get("signInActivity", {})
    
    return {
        "user": {
            "displayName": user.get("displayName"),
            "userPrincipalName": user.get("userPrincipalName"),
        },
        "sign_in_activity": {
            "lastSignInDateTime": sign_in.get("lastSignInDateTime"),
            "lastSignInRequestId": sign_in.get("lastSignInRequestId"),
            "lastNonInteractiveSignInDateTime": sign_in.get("lastNonInteractiveSignInDateTime"),
        }
    }


async def assign_manager(user_id: str, manager_id: str) -> dict[str, Any]:
    """
    Assign a manager to a user.
    
    Args:
        user_id: The user ID or userPrincipalName
        manager_id: The manager's user ID or userPrincipalName
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    user = await client.get(f"/users/{user_id}?$select=displayName,id")
    manager = await client.get(f"/users/{manager_id}?$select=displayName,id")
    
    await client.patch(
        f"/users/{user['id']}/manager/$ref",
        json={"@odata.id": f"https://graph.microsoft.com/v1.0/users/{manager['id']}"}
    )
    
    return {
        "status": "success",
        "message": f"Manager '{manager.get('displayName')}' assigned to user '{user.get('displayName')}'"
    }


async def remove_manager(user_id: str) -> dict[str, Any]:
    """
    Remove the manager assignment from a user.
    
    Args:
        user_id: The user ID or userPrincipalName
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    user = await client.get(f"/users/{user_id}?$select=displayName")
    
    await client.delete(f"/users/{user_id}/manager/$ref")
    
    return {
        "status": "success",
        "message": f"Manager removed from user '{user.get('displayName')}'"
    }


async def get_deleted_users(top: int = 50) -> dict[str, Any]:
    """
    List deleted users (recoverable within 30 days).
    
    Args:
        top: Maximum number of users to return
    
    Returns:
        List of deleted users
    """
    client = get_graph_client()
    
    response = await client.get(f"/directory/deletedItems/microsoft.graph.user?$top={top}")
    users = response.get("value", [])
    
    return {
        "count": len(users),
        "deleted_users": [
            {
                "id": u.get("id"),
                "displayName": u.get("displayName"),
                "userPrincipalName": u.get("userPrincipalName"),
                "deletedDateTime": u.get("deletedDateTime"),
            }
            for u in users
        ]
    }


async def restore_deleted_user(user_id: str) -> dict[str, Any]:
    """
    Restore a deleted user.
    
    Args:
        user_id: The deleted user's ID
    
    Returns:
        Status of the restoration
    """
    client = get_graph_client()
    
    result = await client.post(f"/directory/deletedItems/{user_id}/restore")
    
    return {
        "status": "success",
        "message": f"User '{result.get('displayName')}' restored successfully",
        "user": {
            "id": result.get("id"),
            "displayName": result.get("displayName"),
            "userPrincipalName": result.get("userPrincipalName"),
        }
    }


async def get_user_licenses(user_id: str) -> dict[str, Any]:
    """
    Get detailed license information for a user.
    
    Args:
        user_id: The user ID or userPrincipalName
    
    Returns:
        License assignment details
    """
    client = get_graph_client()
    
    user = await client.get(
        f"/users/{user_id}?$select=displayName,userPrincipalName,assignedLicenses,licenseAssignmentStates"
    )
    
    # Get subscribed SKUs for friendly names
    skus = await client.get("/subscribedSkus")
    sku_map = {s.get("skuId"): s.get("skuPartNumber") for s in skus.get("value", [])}
    
    licenses = []
    for lic in user.get("assignedLicenses", []):
        sku_id = lic.get("skuId")
        licenses.append({
            "skuId": sku_id,
            "skuName": sku_map.get(sku_id, "Unknown"),
            "disabledPlans": lic.get("disabledPlans", [])
        })
    
    return {
        "user": {
            "displayName": user.get("displayName"),
            "userPrincipalName": user.get("userPrincipalName"),
        },
        "license_count": len(licenses),
        "licenses": licenses,
        "license_states": user.get("licenseAssignmentStates", [])
    }


async def assign_license(user_id: str, sku_id: str, disabled_plans: list = None) -> dict[str, Any]:
    """
    Assign a license to a user.
    
    Args:
        user_id: The user ID or userPrincipalName
        sku_id: The SKU ID of the license to assign
        disabled_plans: Optional list of service plan IDs to disable
    
    Returns:
        Status of the license assignment
    """
    client = get_graph_client()
    
    user = await client.get(f"/users/{user_id}?$select=displayName")
    
    license_data = {
        "addLicenses": [
            {
                "skuId": sku_id,
                "disabledPlans": disabled_plans or []
            }
        ],
        "removeLicenses": []
    }
    
    await client.post(f"/users/{user_id}/assignLicense", json=license_data)
    
    return {
        "status": "success",
        "message": f"License assigned to user '{user.get('displayName')}'",
        "sku_id": sku_id
    }


async def remove_license(user_id: str, sku_id: str) -> dict[str, Any]:
    """
    Remove a license from a user.
    
    Args:
        user_id: The user ID or userPrincipalName
        sku_id: The SKU ID of the license to remove
    
    Returns:
        Status of the license removal
    """
    client = get_graph_client()
    
    user = await client.get(f"/users/{user_id}?$select=displayName")
    
    license_data = {
        "addLicenses": [],
        "removeLicenses": [sku_id]
    }
    
    await client.post(f"/users/{user_id}/assignLicense", json=license_data)
    
    return {
        "status": "success",
        "message": f"License removed from user '{user.get('displayName')}'",
        "sku_id": sku_id
    }


async def list_available_licenses() -> dict[str, Any]:
    """
    List all available licenses (SKUs) in the tenant with availability.
    
    Returns:
        List of subscribed SKUs with license counts
    """
    client = get_graph_client()
    
    response = await client.get("/subscribedSkus")
    skus = response.get("value", [])
    
    return {
        "count": len(skus),
        "licenses": [
            {
                "skuId": s.get("skuId"),
                "skuPartNumber": s.get("skuPartNumber"),
                "capabilityStatus": s.get("capabilityStatus"),
                "consumed": s.get("consumedUnits"),
                "total": s.get("prepaidUnits", {}).get("enabled", 0),
                "available": s.get("prepaidUnits", {}).get("enabled", 0) - s.get("consumedUnits", 0),
            }
            for s in skus
        ]
    }

