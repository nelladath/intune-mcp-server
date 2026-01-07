"""
Intune and Entra ID Reports
Comprehensive reporting for devices, compliance, apps, and policies.
"""

from typing import Any
from ..graph_client import get_graph_client


# ============== DEVICE COMPLIANCE REPORTS ==============

async def get_device_compliance_report() -> dict[str, Any]:
    """
    Get overall device compliance summary across all managed devices.
    
    Returns:
        Compliance summary with breakdowns
    """
    client = get_graph_client()
    
    devices = await client.get(
        "/deviceManagement/managedDevices?$select=complianceState,operatingSystem,deviceName&$top=999"
    )
    device_list = devices.get("value", [])
    
    compliance_counts = {}
    os_compliance = {}
    
    for device in device_list:
        state = device.get("complianceState", "unknown")
        os = device.get("operatingSystem", "unknown")
        
        compliance_counts[state] = compliance_counts.get(state, 0) + 1
        
        if os not in os_compliance:
            os_compliance[os] = {"compliant": 0, "noncompliant": 0, "other": 0}
        
        if state == "compliant":
            os_compliance[os]["compliant"] += 1
        elif state == "noncompliant":
            os_compliance[os]["noncompliant"] += 1
        else:
            os_compliance[os]["other"] += 1
    
    total = len(device_list)
    compliant = compliance_counts.get("compliant", 0)
    
    return {
        "summary": {
            "total_devices": total,
            "compliant": compliant,
            "noncompliant": compliance_counts.get("noncompliant", 0),
            "compliance_percentage": round((compliant / total) * 100, 2) if total > 0 else 0,
        },
        "by_compliance_state": compliance_counts,
        "by_operating_system": os_compliance,
    }


async def get_device_configuration_status(profile_id: str) -> dict[str, Any]:
    """
    Get deployment status for a specific configuration profile.
    
    Args:
        profile_id: The configuration profile ID
    
    Returns:
        Deployment status with success/failure counts
    """
    client = get_graph_client()
    
    # Get profile info
    profile = await client.get(f"/deviceManagement/deviceConfigurations/{profile_id}")
    
    # Get device statuses
    statuses = await client.get(
        f"/deviceManagement/deviceConfigurations/{profile_id}/deviceStatuses?$top=999"
    )
    status_list = statuses.get("value", [])
    
    # Count by status
    status_counts = {}
    failed_devices = []
    
    for status in status_list:
        state = status.get("status", "unknown")
        status_counts[state] = status_counts.get(state, 0) + 1
        
        if state in ["error", "conflict", "notApplicable"]:
            failed_devices.append({
                "deviceDisplayName": status.get("deviceDisplayName"),
                "userPrincipalName": status.get("userPrincipalName"),
                "status": state,
                "lastReportedDateTime": status.get("lastReportedDateTime"),
            })
    
    total = len(status_list)
    succeeded = status_counts.get("succeeded", 0) + status_counts.get("notApplicable", 0)
    
    return {
        "profile": {
            "id": profile.get("id"),
            "displayName": profile.get("displayName"),
            "description": profile.get("description"),
        },
        "summary": {
            "total_devices": total,
            "succeeded": status_counts.get("succeeded", 0),
            "pending": status_counts.get("pending", 0),
            "error": status_counts.get("error", 0),
            "conflict": status_counts.get("conflict", 0),
            "not_applicable": status_counts.get("notApplicable", 0),
            "success_rate": round((succeeded / total) * 100, 2) if total > 0 else 0,
        },
        "status_breakdown": status_counts,
        "failed_devices": failed_devices[:20],  # Limit to first 20
    }


async def get_compliance_policy_status(policy_id: str) -> dict[str, Any]:
    """
    Get deployment status for a specific compliance policy.
    
    Args:
        policy_id: The compliance policy ID
    
    Returns:
        Deployment status with success/failure counts
    """
    client = get_graph_client()
    
    # Get policy info
    policy = await client.get(f"/deviceManagement/deviceCompliancePolicies/{policy_id}")
    
    # Get device statuses
    statuses = await client.get(
        f"/deviceManagement/deviceCompliancePolicies/{policy_id}/deviceStatuses?$top=999"
    )
    status_list = statuses.get("value", [])
    
    # Count by status
    status_counts = {}
    noncompliant_devices = []
    
    for status in status_list:
        state = status.get("status", "unknown")
        status_counts[state] = status_counts.get(state, 0) + 1
        
        if state in ["nonCompliant", "error", "conflict"]:
            noncompliant_devices.append({
                "deviceDisplayName": status.get("deviceDisplayName"),
                "userName": status.get("userName"),
                "status": state,
                "lastReportedDateTime": status.get("lastReportedDateTime"),
                "complianceGracePeriodExpirationDateTime": status.get("complianceGracePeriodExpirationDateTime"),
            })
    
    total = len(status_list)
    compliant = status_counts.get("compliant", 0)
    
    return {
        "policy": {
            "id": policy.get("id"),
            "displayName": policy.get("displayName"),
            "description": policy.get("description"),
        },
        "summary": {
            "total_devices": total,
            "compliant": compliant,
            "noncompliant": status_counts.get("nonCompliant", 0),
            "in_grace_period": status_counts.get("inGracePeriod", 0),
            "error": status_counts.get("error", 0),
            "compliance_rate": round((compliant / total) * 100, 2) if total > 0 else 0,
        },
        "status_breakdown": status_counts,
        "noncompliant_devices": noncompliant_devices[:20],
    }


# ============== APP DEPLOYMENT REPORTS ==============

async def get_app_installation_status(app_id: str) -> dict[str, Any]:
    """
    Get installation status for a specific app.
    
    Args:
        app_id: The app ID
    
    Returns:
        Installation status with success/failure counts
    """
    client = get_graph_client()
    
    # Get app info
    app = await client.get(f"/deviceAppManagement/mobileApps/{app_id}")
    
    # Get device install statuses
    try:
        statuses = await client.get(
            f"/deviceAppManagement/mobileApps/{app_id}/deviceStatuses?$top=999"
        )
        status_list = statuses.get("value", [])
    except:
        status_list = []
    
    # Count by status
    status_counts = {}
    failed_installs = []
    
    for status in status_list:
        state = status.get("installState", "unknown")
        status_counts[state] = status_counts.get(state, 0) + 1
        
        if state in ["failed", "notInstalled"]:
            failed_installs.append({
                "deviceName": status.get("deviceName"),
                "userName": status.get("userName"),
                "installState": state,
                "errorCode": status.get("errorCode"),
                "lastSyncDateTime": status.get("lastSyncDateTime"),
            })
    
    total = len(status_list)
    installed = status_counts.get("installed", 0)
    
    return {
        "app": {
            "id": app.get("id"),
            "displayName": app.get("displayName"),
            "publisher": app.get("publisher"),
        },
        "summary": {
            "total_targeted": total,
            "installed": installed,
            "pending": status_counts.get("pendingInstall", 0) + status_counts.get("notInstalled", 0),
            "failed": status_counts.get("failed", 0),
            "install_success_rate": round((installed / total) * 100, 2) if total > 0 else 0,
        },
        "status_breakdown": status_counts,
        "failed_installs": failed_installs[:20],
    }


async def get_app_overview_report() -> dict[str, Any]:
    """
    Get an overview of all app deployments.
    
    Returns:
        Summary of app deployment statistics
    """
    client = get_graph_client()
    
    apps = await client.get("/deviceAppManagement/mobileApps?$top=100")
    app_list = apps.get("value", [])
    
    # Categorize apps by type
    app_types = {}
    for app in app_list:
        app_type = app.get("@odata.type", "").replace("#microsoft.graph.", "")
        app_types[app_type] = app_types.get(app_type, 0) + 1
    
    return {
        "total_apps": len(app_list),
        "by_type": app_types,
        "apps": [
            {
                "id": app.get("id"),
                "displayName": app.get("displayName"),
                "publisher": app.get("publisher"),
                "type": app.get("@odata.type", "").replace("#microsoft.graph.", ""),
            }
            for app in app_list
        ]
    }


# ============== WINDOWS UPDATE REPORTS ==============

async def get_windows_update_status() -> dict[str, Any]:
    """
    Get Windows Update compliance status for all Windows devices.
    
    Returns:
        Windows Update status summary
    """
    client = get_graph_client()
    
    # Get Windows devices
    devices = await client.get(
        "/deviceManagement/managedDevices?$filter=operatingSystem eq 'Windows'&$select=deviceName,osVersion,userPrincipalName,lastSyncDateTime&$top=999"
    )
    device_list = devices.get("value", [])
    
    # Group by OS version
    version_counts = {}
    for device in device_list:
        version = device.get("osVersion", "Unknown")
        version_counts[version] = version_counts.get(version, 0) + 1
    
    return {
        "total_windows_devices": len(device_list),
        "by_os_version": version_counts,
        "devices": [
            {
                "deviceName": d.get("deviceName"),
                "osVersion": d.get("osVersion"),
                "userPrincipalName": d.get("userPrincipalName"),
                "lastSyncDateTime": d.get("lastSyncDateTime"),
            }
            for d in device_list[:50]  # Limit response
        ]
    }


# ============== ENROLLMENT REPORTS ==============

async def get_enrollment_status_report() -> dict[str, Any]:
    """
    Get device enrollment status summary.
    
    Returns:
        Enrollment statistics
    """
    client = get_graph_client()
    
    devices = await client.get(
        "/deviceManagement/managedDevices?$select=deviceEnrollmentType,managementAgent,operatingSystem,enrolledDateTime&$top=999"
    )
    device_list = devices.get("value", [])
    
    # Group by enrollment type
    enrollment_types = {}
    management_agents = {}
    os_counts = {}
    
    for device in device_list:
        etype = device.get("deviceEnrollmentType", "unknown")
        agent = device.get("managementAgent", "unknown")
        os = device.get("operatingSystem", "unknown")
        
        enrollment_types[etype] = enrollment_types.get(etype, 0) + 1
        management_agents[agent] = management_agents.get(agent, 0) + 1
        os_counts[os] = os_counts.get(os, 0) + 1
    
    # Calculate recent enrollments (last 30 days)
    from datetime import datetime, timedelta
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_enrollments = sum(
        1 for d in device_list 
        if d.get("enrolledDateTime") and 
        datetime.fromisoformat(d["enrolledDateTime"].replace("Z", "+00:00")).replace(tzinfo=None) > thirty_days_ago
    )
    
    return {
        "summary": {
            "total_enrolled": len(device_list),
            "enrolled_last_30_days": recent_enrollments,
        },
        "by_enrollment_type": enrollment_types,
        "by_management_agent": management_agents,
        "by_operating_system": os_counts,
    }


# ============== POLICY ASSIGNMENT REPORTS ==============

async def get_policy_assignments_report() -> dict[str, Any]:
    """
    Get a summary of all policy assignments (compliance, configuration, app protection).
    
    Returns:
        Policy assignment summary
    """
    client = get_graph_client()
    
    # Get compliance policies
    compliance = await client.get("/deviceManagement/deviceCompliancePolicies")
    compliance_policies = compliance.get("value", [])
    
    # Get configuration profiles
    configs = await client.get("/deviceManagement/deviceConfigurations")
    config_profiles = configs.get("value", [])
    
    # Get app protection policies
    try:
        app_protection = await client.get("/deviceAppManagement/managedAppPolicies")
        app_policies = app_protection.get("value", [])
    except:
        app_policies = []
    
    return {
        "summary": {
            "compliance_policies": len(compliance_policies),
            "configuration_profiles": len(config_profiles),
            "app_protection_policies": len(app_policies),
        },
        "compliance_policies": [
            {"id": p.get("id"), "displayName": p.get("displayName")}
            for p in compliance_policies
        ],
        "configuration_profiles": [
            {"id": c.get("id"), "displayName": c.get("displayName")}
            for c in config_profiles
        ],
        "app_protection_policies": [
            {"id": a.get("id"), "displayName": a.get("displayName")}
            for a in app_policies
        ],
    }


# ============== SECURITY REPORTS ==============

async def get_device_security_report() -> dict[str, Any]:
    """
    Get security status of managed devices (encryption, defender, etc.).
    
    Returns:
        Device security summary
    """
    client = get_graph_client()
    
    devices = await client.get(
        "/deviceManagement/managedDevices?$select=deviceName,isEncrypted,complianceState,operatingSystem&$top=999"
    )
    device_list = devices.get("value", [])
    
    encrypted = sum(1 for d in device_list if d.get("isEncrypted"))
    not_encrypted = sum(1 for d in device_list if d.get("isEncrypted") == False)
    unknown_encryption = len(device_list) - encrypted - not_encrypted
    
    return {
        "total_devices": len(device_list),
        "encryption_status": {
            "encrypted": encrypted,
            "not_encrypted": not_encrypted,
            "unknown": unknown_encryption,
            "encryption_rate": round((encrypted / len(device_list)) * 100, 2) if device_list else 0,
        },
        "devices_needing_attention": [
            {
                "deviceName": d.get("deviceName"),
                "isEncrypted": d.get("isEncrypted"),
                "complianceState": d.get("complianceState"),
            }
            for d in device_list 
            if d.get("isEncrypted") == False or d.get("complianceState") == "noncompliant"
        ][:20]
    }


# ============== HARDWARE INVENTORY REPORTS ==============

async def get_hardware_inventory_report() -> dict[str, Any]:
    """
    Get hardware inventory summary for all managed devices.
    
    Returns:
        Hardware inventory statistics
    """
    client = get_graph_client()
    
    devices = await client.get(
        "/deviceManagement/managedDevices?$select=deviceName,manufacturer,model,operatingSystem,osVersion,totalStorageSpaceInBytes,freeStorageSpaceInBytes&$top=999"
    )
    device_list = devices.get("value", [])
    
    # Group by manufacturer
    manufacturers = {}
    models = {}
    
    for device in device_list:
        mfr = device.get("manufacturer", "Unknown")
        model = device.get("model", "Unknown")
        
        manufacturers[mfr] = manufacturers.get(mfr, 0) + 1
        models[model] = models.get(model, 0) + 1
    
    # Sort by count
    top_manufacturers = dict(sorted(manufacturers.items(), key=lambda x: x[1], reverse=True)[:10])
    top_models = dict(sorted(models.items(), key=lambda x: x[1], reverse=True)[:10])
    
    return {
        "total_devices": len(device_list),
        "by_manufacturer": top_manufacturers,
        "by_model": top_models,
    }


# ============== USER LICENSE REPORTS ==============

async def get_license_usage_report() -> dict[str, Any]:
    """
    Get license usage summary across the tenant.
    
    Returns:
        License usage statistics
    """
    client = get_graph_client()
    
    skus = await client.get("/subscribedSkus")
    sku_list = skus.get("value", [])
    
    licenses = []
    total_assigned = 0
    total_available = 0
    
    for sku in sku_list:
        enabled = sku.get("prepaidUnits", {}).get("enabled", 0)
        consumed = sku.get("consumedUnits", 0)
        available = enabled - consumed
        
        total_assigned += consumed
        total_available += available
        
        licenses.append({
            "skuPartNumber": sku.get("skuPartNumber"),
            "skuId": sku.get("skuId"),
            "capabilityStatus": sku.get("capabilityStatus"),
            "total": enabled,
            "assigned": consumed,
            "available": available,
            "usage_percentage": round((consumed / enabled) * 100, 2) if enabled > 0 else 0,
        })
    
    return {
        "summary": {
            "total_sku_types": len(sku_list),
            "total_assigned_licenses": total_assigned,
            "total_available_licenses": total_available,
        },
        "licenses": sorted(licenses, key=lambda x: x.get("usage_percentage", 0), reverse=True),
    }


# ============== EXPORT FUNCTIONS ==============

async def generate_compliance_export() -> dict[str, Any]:
    """
    Generate a comprehensive compliance report suitable for export.
    
    Returns:
        Full compliance data for all devices
    """
    client = get_graph_client()
    
    devices = await client.get(
        "/deviceManagement/managedDevices?$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState,isEncrypted,lastSyncDateTime,serialNumber,manufacturer,model&$top=999"
    )
    device_list = devices.get("value", [])
    
    return {
        "generated_at": __import__('datetime').datetime.utcnow().isoformat() + "Z",
        "total_devices": len(device_list),
        "devices": device_list,
    }

