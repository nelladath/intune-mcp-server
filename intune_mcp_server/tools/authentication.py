"""
Authentication and Identity Protection Tools
MFA management, authentication methods, sign-in logs, and identity protection.
"""

from typing import Any
from ..graph_client import get_graph_client


# ============== AUTHENTICATION METHODS ==============

async def get_user_authentication_methods(user_id: str) -> dict[str, Any]:
    """
    Get all authentication methods registered for a user.
    
    Args:
        user_id: The user ID or userPrincipalName
    
    Returns:
        List of registered authentication methods
    """
    client = get_graph_client()
    
    user = await client.get(f"/users/{user_id}?$select=displayName,userPrincipalName")
    
    methods = await client.get(f"/users/{user_id}/authentication/methods")
    method_list = methods.get("value", [])
    
    return {
        "user": {
            "displayName": user.get("displayName"),
            "userPrincipalName": user.get("userPrincipalName"),
        },
        "method_count": len(method_list),
        "methods": [
            {
                "id": m.get("id"),
                "type": m.get("@odata.type", "").replace("#microsoft.graph.", ""),
                "details": _extract_method_details(m)
            }
            for m in method_list
        ]
    }


def _extract_method_details(method: dict) -> dict:
    """Extract relevant details from an authentication method."""
    method_type = method.get("@odata.type", "")
    
    if "phoneAuthenticationMethod" in method_type:
        return {
            "phoneNumber": method.get("phoneNumber"),
            "phoneType": method.get("phoneType"),
        }
    elif "emailAuthenticationMethod" in method_type:
        return {
            "emailAddress": method.get("emailAddress"),
        }
    elif "microsoftAuthenticatorAuthenticationMethod" in method_type:
        return {
            "displayName": method.get("displayName"),
            "deviceTag": method.get("deviceTag"),
            "phoneAppVersion": method.get("phoneAppVersion"),
        }
    elif "fido2AuthenticationMethod" in method_type:
        return {
            "displayName": method.get("displayName"),
            "model": method.get("model"),
            "attestationLevel": method.get("attestationLevel"),
        }
    elif "windowsHelloForBusinessAuthenticationMethod" in method_type:
        return {
            "displayName": method.get("displayName"),
            "keyStrength": method.get("keyStrength"),
        }
    elif "passwordAuthenticationMethod" in method_type:
        return {
            "createdDateTime": method.get("createdDateTime"),
        }
    else:
        return {}


async def get_user_mfa_status(user_id: str) -> dict[str, Any]:
    """
    Get MFA status and registered methods for a user.
    
    Args:
        user_id: The user ID or userPrincipalName
    
    Returns:
        MFA status and method summary
    """
    client = get_graph_client()
    
    user = await client.get(f"/users/{user_id}?$select=displayName,userPrincipalName")
    
    methods = await client.get(f"/users/{user_id}/authentication/methods")
    method_list = methods.get("value", [])
    
    # Categorize methods
    has_phone = False
    has_email = False
    has_authenticator = False
    has_fido2 = False
    has_windows_hello = False
    
    for m in method_list:
        method_type = m.get("@odata.type", "")
        if "phoneAuthenticationMethod" in method_type:
            has_phone = True
        elif "emailAuthenticationMethod" in method_type:
            has_email = True
        elif "microsoftAuthenticatorAuthenticationMethod" in method_type:
            has_authenticator = True
        elif "fido2AuthenticationMethod" in method_type:
            has_fido2 = True
        elif "windowsHelloForBusinessAuthenticationMethod" in method_type:
            has_windows_hello = True
    
    # Determine MFA capability
    mfa_capable = has_phone or has_authenticator or has_fido2 or has_windows_hello
    
    return {
        "user": {
            "displayName": user.get("displayName"),
            "userPrincipalName": user.get("userPrincipalName"),
        },
        "mfa_capable": mfa_capable,
        "registered_methods": {
            "phone": has_phone,
            "email": has_email,
            "microsoft_authenticator": has_authenticator,
            "fido2_security_key": has_fido2,
            "windows_hello": has_windows_hello,
        },
        "total_methods": len(method_list),
        "recommendation": "User is MFA capable" if mfa_capable else "⚠️ User needs to register MFA methods"
    }


async def delete_user_authentication_method(
    user_id: str,
    method_id: str,
    method_type: str,
    confirm: bool = False
) -> dict[str, Any]:
    """
    Delete a specific authentication method for a user.
    
    Args:
        user_id: The user ID or userPrincipalName
        method_id: The authentication method ID
        method_type: Type of method (phone, email, microsoftAuthenticator, fido2)
        confirm: Must be True to execute deletion
    
    Returns:
        Deletion status
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "⚠️ This will delete the authentication method! Set confirm=True to proceed."
        }
    
    client = get_graph_client()
    
    type_endpoints = {
        "phone": "phoneMethods",
        "email": "emailMethods",
        "microsoftAuthenticator": "microsoftAuthenticatorMethods",
        "fido2": "fido2Methods",
        "windowsHelloForBusiness": "windowsHelloForBusinessMethods",
    }
    
    endpoint = type_endpoints.get(method_type)
    if not endpoint:
        return {"status": "error", "message": f"Invalid method type: {method_type}"}
    
    await client.delete(f"/users/{user_id}/authentication/{endpoint}/{method_id}")
    
    return {
        "status": "success",
        "message": f"Authentication method deleted for user"
    }


async def add_user_phone_method(
    user_id: str,
    phone_number: str,
    phone_type: str = "mobile"
) -> dict[str, Any]:
    """
    Add a phone authentication method for a user.
    
    Args:
        user_id: The user ID or userPrincipalName
        phone_number: Phone number in E.164 format (e.g., +1 5555551234)
        phone_type: "mobile", "alternateMobile", or "office"
    
    Returns:
        Created method details
    """
    client = get_graph_client()
    
    method_data = {
        "phoneNumber": phone_number,
        "phoneType": phone_type
    }
    
    result = await client.post(
        f"/users/{user_id}/authentication/phoneMethods",
        json=method_data
    )
    
    return {
        "status": "success",
        "message": f"Phone authentication method added",
        "method": {
            "id": result.get("id"),
            "phoneNumber": result.get("phoneNumber"),
            "phoneType": result.get("phoneType"),
        }
    }


# ============== SIGN-IN LOGS ==============

async def get_sign_in_logs(
    top: int = 50,
    user_id: str = None,
    app_id: str = None,
    status: str = None,
    days_back: int = 7
) -> dict[str, Any]:
    """
    Get sign-in logs with optional filtering.
    
    Args:
        top: Maximum number of logs to return
        user_id: Filter by user ID
        app_id: Filter by application ID
        status: Filter by status ("success", "failure")
        days_back: Number of days to look back (default 7)
    
    Returns:
        Sign-in log entries
    """
    client = get_graph_client()
    
    from datetime import datetime, timedelta
    cutoff_date = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    filters = [f"createdDateTime ge {cutoff_date}"]
    
    if user_id:
        filters.append(f"userId eq '{user_id}'")
    if app_id:
        filters.append(f"appId eq '{app_id}'")
    if status == "success":
        filters.append("status/errorCode eq 0")
    elif status == "failure":
        filters.append("status/errorCode ne 0")
    
    filter_query = " and ".join(filters)
    endpoint = f"/auditLogs/signIns?$filter={filter_query}&$top={top}&$orderby=createdDateTime desc"
    
    response = await client.get(endpoint)
    logs = response.get("value", [])
    
    return {
        "count": len(logs),
        "sign_ins": [
            {
                "id": log.get("id"),
                "createdDateTime": log.get("createdDateTime"),
                "user": {
                    "id": log.get("userId"),
                    "displayName": log.get("userDisplayName"),
                    "userPrincipalName": log.get("userPrincipalName"),
                },
                "app": {
                    "id": log.get("appId"),
                    "displayName": log.get("appDisplayName"),
                },
                "status": {
                    "errorCode": log.get("status", {}).get("errorCode"),
                    "failureReason": log.get("status", {}).get("failureReason"),
                },
                "location": {
                    "city": log.get("location", {}).get("city"),
                    "state": log.get("location", {}).get("state"),
                    "countryOrRegion": log.get("location", {}).get("countryOrRegion"),
                },
                "device": {
                    "browser": log.get("deviceDetail", {}).get("browser"),
                    "operatingSystem": log.get("deviceDetail", {}).get("operatingSystem"),
                },
                "ipAddress": log.get("ipAddress"),
                "clientAppUsed": log.get("clientAppUsed"),
                "conditionalAccessStatus": log.get("conditionalAccessStatus"),
                "isInteractive": log.get("isInteractive"),
                "riskDetail": log.get("riskDetail"),
                "riskLevelDuringSignIn": log.get("riskLevelDuringSignIn"),
            }
            for log in logs
        ]
    }


async def get_user_sign_in_logs(user_id: str, top: int = 50) -> dict[str, Any]:
    """
    Get sign-in logs for a specific user.
    
    Args:
        user_id: The user ID or userPrincipalName
        top: Maximum number of logs to return
    
    Returns:
        User's sign-in log entries
    """
    client = get_graph_client()
    
    # Get user info first
    user = await client.get(f"/users/{user_id}?$select=id,displayName,userPrincipalName")
    
    endpoint = f"/auditLogs/signIns?$filter=userId eq '{user['id']}'&$top={top}&$orderby=createdDateTime desc"
    
    response = await client.get(endpoint)
    logs = response.get("value", [])
    
    return {
        "user": {
            "displayName": user.get("displayName"),
            "userPrincipalName": user.get("userPrincipalName"),
        },
        "count": len(logs),
        "sign_ins": [
            {
                "createdDateTime": log.get("createdDateTime"),
                "appDisplayName": log.get("appDisplayName"),
                "status": log.get("status", {}).get("errorCode", 0) == 0,
                "failureReason": log.get("status", {}).get("failureReason"),
                "ipAddress": log.get("ipAddress"),
                "location": log.get("location", {}).get("city"),
                "browser": log.get("deviceDetail", {}).get("browser"),
                "os": log.get("deviceDetail", {}).get("operatingSystem"),
            }
            for log in logs
        ]
    }


async def get_failed_sign_ins(top: int = 50, days_back: int = 7) -> dict[str, Any]:
    """
    Get failed sign-in attempts.
    
    Args:
        top: Maximum number of logs to return
        days_back: Number of days to look back
    
    Returns:
        Failed sign-in entries
    """
    return await get_sign_in_logs(top=top, status="failure", days_back=days_back)


# ============== IDENTITY PROTECTION ==============

async def get_risky_users(top: int = 50, risk_level: str = None) -> dict[str, Any]:
    """
    Get users flagged as risky by Identity Protection.
    
    Args:
        top: Maximum number of users to return
        risk_level: Filter by level ("low", "medium", "high")
    
    Returns:
        List of risky users
    """
    client = get_graph_client()
    
    endpoint = f"/identityProtection/riskyUsers?$top={top}"
    
    if risk_level:
        endpoint += f"&$filter=riskLevel eq '{risk_level}'"
    
    response = await client.get(endpoint)
    users = response.get("value", [])
    
    return {
        "count": len(users),
        "risky_users": [
            {
                "id": u.get("id"),
                "userDisplayName": u.get("userDisplayName"),
                "userPrincipalName": u.get("userPrincipalName"),
                "riskLevel": u.get("riskLevel"),
                "riskState": u.get("riskState"),
                "riskDetail": u.get("riskDetail"),
                "riskLastUpdatedDateTime": u.get("riskLastUpdatedDateTime"),
                "isProcessing": u.get("isProcessing"),
                "isDeleted": u.get("isDeleted"),
            }
            for u in users
        ]
    }


async def get_risk_detections(top: int = 50, days_back: int = 7) -> dict[str, Any]:
    """
    Get risk detections from Identity Protection.
    
    Args:
        top: Maximum number of detections to return
        days_back: Number of days to look back
    
    Returns:
        List of risk detections
    """
    client = get_graph_client()
    
    from datetime import datetime, timedelta
    cutoff_date = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    endpoint = f"/identityProtection/riskDetections?$filter=detectedDateTime ge {cutoff_date}&$top={top}&$orderby=detectedDateTime desc"
    
    response = await client.get(endpoint)
    detections = response.get("value", [])
    
    return {
        "count": len(detections),
        "risk_detections": [
            {
                "id": d.get("id"),
                "userDisplayName": d.get("userDisplayName"),
                "userPrincipalName": d.get("userPrincipalName"),
                "riskType": d.get("riskType"),
                "riskEventType": d.get("riskEventType"),
                "riskLevel": d.get("riskLevel"),
                "riskState": d.get("riskState"),
                "riskDetail": d.get("riskDetail"),
                "detectedDateTime": d.get("detectedDateTime"),
                "ipAddress": d.get("ipAddress"),
                "location": {
                    "city": d.get("location", {}).get("city"),
                    "countryOrRegion": d.get("location", {}).get("countryOrRegion"),
                },
                "source": d.get("source"),
                "detectionTimingType": d.get("detectionTimingType"),
            }
            for d in detections
        ]
    }


async def dismiss_risky_user(user_id: str) -> dict[str, Any]:
    """
    Dismiss the risk for a user (mark as false positive).
    
    Args:
        user_id: The risky user ID
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    await client.post(
        "/identityProtection/riskyUsers/dismiss",
        json={"userIds": [user_id]}
    )
    
    return {
        "status": "success",
        "message": f"Risk dismissed for user {user_id}"
    }


async def confirm_risky_user_compromised(user_id: str) -> dict[str, Any]:
    """
    Confirm that a user has been compromised.
    
    Args:
        user_id: The risky user ID
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    await client.post(
        "/identityProtection/riskyUsers/confirmCompromised",
        json={"userIds": [user_id]}
    )
    
    return {
        "status": "success",
        "message": f"User {user_id} confirmed as compromised"
    }


# ============== AUDIT LOGS ==============

async def get_directory_audit_logs(
    top: int = 50,
    category: str = None,
    activity: str = None,
    days_back: int = 7
) -> dict[str, Any]:
    """
    Get directory audit logs.
    
    Args:
        top: Maximum number of logs to return
        category: Filter by category (e.g., "UserManagement", "GroupManagement")
        activity: Filter by activity type
        days_back: Number of days to look back
    
    Returns:
        Audit log entries
    """
    client = get_graph_client()
    
    from datetime import datetime, timedelta
    cutoff_date = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    filters = [f"activityDateTime ge {cutoff_date}"]
    
    if category:
        filters.append(f"category eq '{category}'")
    if activity:
        filters.append(f"activityDisplayName eq '{activity}'")
    
    filter_query = " and ".join(filters)
    endpoint = f"/auditLogs/directoryAudits?$filter={filter_query}&$top={top}&$orderby=activityDateTime desc"
    
    response = await client.get(endpoint)
    logs = response.get("value", [])
    
    return {
        "count": len(logs),
        "audit_logs": [
            {
                "id": log.get("id"),
                "activityDateTime": log.get("activityDateTime"),
                "activityDisplayName": log.get("activityDisplayName"),
                "category": log.get("category"),
                "result": log.get("result"),
                "resultReason": log.get("resultReason"),
                "initiatedBy": {
                    "user": (log.get("initiatedBy") or {}).get("user", {}).get("userPrincipalName") if (log.get("initiatedBy") or {}).get("user") else None,
                    "app": (log.get("initiatedBy") or {}).get("app", {}).get("displayName") if (log.get("initiatedBy") or {}).get("app") else None,
                },
                "targetResources": [
                    {
                        "displayName": t.get("displayName"),
                        "type": t.get("type"),
                    }
                    for t in (log.get("targetResources") or [])
                ],
            }
            for log in logs
        ]
    }


async def get_user_activity_audit(user_id: str, top: int = 50) -> dict[str, Any]:
    """
    Get audit logs for activities performed by or on a specific user.
    
    Args:
        user_id: The user ID or userPrincipalName
        top: Maximum number of logs to return
    
    Returns:
        User-related audit entries
    """
    client = get_graph_client()
    
    user = await client.get(f"/users/{user_id}?$select=id,displayName,userPrincipalName")
    
    # Get logs where user initiated the action
    initiated_logs = await client.get(
        f"/auditLogs/directoryAudits?$filter=initiatedBy/user/id eq '{user['id']}'&$top={top}&$orderby=activityDateTime desc"
    )
    
    return {
        "user": {
            "displayName": user.get("displayName"),
            "userPrincipalName": user.get("userPrincipalName"),
        },
        "count": len(initiated_logs.get("value", [])),
        "activities": [
            {
                "activityDateTime": log.get("activityDateTime"),
                "activityDisplayName": log.get("activityDisplayName"),
                "category": log.get("category"),
                "result": log.get("result"),
                "targetResources": [t.get("displayName") for t in log.get("targetResources", [])],
            }
            for log in initiated_logs.get("value", [])
        ]
    }


# ============== PASSWORD POLICIES ==============

async def get_password_policies() -> dict[str, Any]:
    """
    Get tenant password policies.
    
    Returns:
        Password policy settings
    """
    client = get_graph_client()
    
    # Get organization password policies
    org = await client.get("/organization")
    org_info = org.get("value", [{}])[0]
    
    # Get authentication methods policy
    try:
        auth_policy = await client.get("/policies/authenticationMethodsPolicy", use_beta=True)
    except:
        auth_policy = {}
    
    return {
        "organization": {
            "displayName": org_info.get("displayName"),
        },
        "password_policies": {
            "note": "Check Azure Portal for detailed password policies",
        },
        "authentication_methods_policy": {
            "registrationEnforcement": auth_policy.get("registrationEnforcement"),
        }
    }


async def get_mfa_registration_report() -> dict[str, Any]:
    """
    Get MFA registration status across all users.
    
    Returns:
        MFA registration summary
    """
    client = get_graph_client()
    
    # Get credential user registration details (beta)
    try:
        response = await client.get(
            "/reports/credentialUserRegistrationDetails",
            use_beta=True
        )
        details = response.get("value", [])
        
        mfa_registered = sum(1 for d in details if d.get("isMfaRegistered"))
        sspr_registered = sum(1 for d in details if d.get("isSsprRegistered"))
        
        return {
            "total_users": len(details),
            "mfa_registered": mfa_registered,
            "mfa_not_registered": len(details) - mfa_registered,
            "sspr_registered": sspr_registered,
            "sspr_not_registered": len(details) - sspr_registered,
            "mfa_registration_percentage": round((mfa_registered / len(details)) * 100, 2) if details else 0,
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Could not retrieve MFA registration report: {str(e)}",
            "note": "This report requires appropriate permissions"
        }

