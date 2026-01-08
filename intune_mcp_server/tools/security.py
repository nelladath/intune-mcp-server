"""
Intune Security and Endpoint Protection Tools
Security baselines, endpoint security policies, and Defender management.
"""

from typing import Any
from ..graph_client import get_graph_client


# ============== SECURITY BASELINES ==============

async def list_security_baselines() -> dict[str, Any]:
    """
    List all security baseline templates available.
    
    Returns:
        List of security baseline templates
    """
    client = get_graph_client()
    
    response = await client.get(
        "/deviceManagement/templates?$filter=templateType eq 'securityBaseline'",
        use_beta=True
    )
    templates = response.get("value", [])
    
    return {
        "count": len(templates),
        "templates": [
            {
                "id": t.get("id"),
                "displayName": t.get("displayName"),
                "description": t.get("description"),
                "versionInfo": t.get("versionInfo"),
                "isDeprecated": t.get("isDeprecated"),
                "intentCount": t.get("intentCount"),
            }
            for t in templates
        ]
    }


async def list_security_baseline_profiles() -> dict[str, Any]:
    """
    List all deployed security baseline profiles.
    
    Returns:
        List of security baseline profile deployments
    """
    client = get_graph_client()
    
    response = await client.get(
        "/deviceManagement/intents?$filter=templateId ne null",
        use_beta=True
    )
    intents = response.get("value", [])
    
    return {
        "count": len(intents),
        "profiles": [
            {
                "id": i.get("id"),
                "displayName": i.get("displayName"),
                "description": i.get("description"),
                "templateId": i.get("templateId"),
                "isAssigned": i.get("isAssigned"),
                "lastModifiedDateTime": i.get("lastModifiedDateTime"),
            }
            for i in intents
        ]
    }


async def get_security_baseline_status(intent_id: str) -> dict[str, Any]:
    """
    Get deployment status for a security baseline profile.
    
    Args:
        intent_id: The security baseline intent/profile ID
    
    Returns:
        Deployment status summary
    """
    client = get_graph_client()
    
    intent = await client.get(
        f"/deviceManagement/intents/{intent_id}",
        use_beta=True
    )
    
    # Get device states
    try:
        states = await client.get(
            f"/deviceManagement/intents/{intent_id}/deviceStates?$top=100",
            use_beta=True
        )
        device_states = states.get("value", [])
    except:
        device_states = []
    
    # Count by state
    state_counts = {}
    for ds in device_states:
        state = ds.get("state", "unknown")
        state_counts[state] = state_counts.get(state, 0) + 1
    
    return {
        "profile": {
            "id": intent_id,
            "displayName": intent.get("displayName"),
        },
        "summary": {
            "total_devices": len(device_states),
            "by_state": state_counts,
        },
        "device_states": [
            {
                "deviceDisplayName": ds.get("deviceDisplayName"),
                "userPrincipalName": ds.get("userPrincipalName"),
                "state": ds.get("state"),
                "lastReportedDateTime": ds.get("lastReportedDateTime"),
            }
            for ds in device_states[:20]
        ]
    }


# ============== ENDPOINT SECURITY ==============

async def list_endpoint_security_policies(category: str = None) -> dict[str, Any]:
    """
    List endpoint security policies.
    
    Args:
        category: Filter by category (e.g., "antivirus", "diskEncryption", "firewall", "endpointDetectionAndResponse", "attackSurfaceReduction", "accountProtection")
    
    Returns:
        List of endpoint security policies
    """
    client = get_graph_client()
    
    # Endpoint security policies are under intents
    endpoint = "/deviceManagement/intents"
    if category:
        # Map categories to template IDs where possible
        endpoint += f"?$filter=contains(templateId, '{category}')"
    
    response = await client.get(endpoint, use_beta=True)
    policies = response.get("value", [])
    
    return {
        "count": len(policies),
        "policies": [
            {
                "id": p.get("id"),
                "displayName": p.get("displayName"),
                "description": p.get("description"),
                "templateId": p.get("templateId"),
                "isAssigned": p.get("isAssigned"),
                "lastModifiedDateTime": p.get("lastModifiedDateTime"),
            }
            for p in policies
        ]
    }


# ============== ANTIVIRUS POLICIES ==============

async def list_antivirus_policies() -> dict[str, Any]:
    """
    List Microsoft Defender Antivirus policies.
    
    Returns:
        List of antivirus configuration policies
    """
    client = get_graph_client()
    
    # Get antivirus configurations
    response = await client.get(
        "/deviceManagement/deviceConfigurations?$filter=contains(@odata.type, 'defender') or contains(@odata.type, 'antivirus')",
        use_beta=True
    )
    policies = response.get("value", [])
    
    return {
        "count": len(policies),
        "policies": [
            {
                "id": p.get("id"),
                "displayName": p.get("displayName"),
                "description": p.get("description"),
                "type": p.get("@odata.type", "").replace("#microsoft.graph.", ""),
                "createdDateTime": p.get("createdDateTime"),
                "lastModifiedDateTime": p.get("lastModifiedDateTime"),
            }
            for p in policies
        ]
    }


# ============== DISK ENCRYPTION ==============

async def list_disk_encryption_policies() -> dict[str, Any]:
    """
    List BitLocker and FileVault disk encryption policies.
    
    Returns:
        List of disk encryption policies
    """
    client = get_graph_client()
    
    response = await client.get(
        "/deviceManagement/deviceConfigurations?$filter=contains(@odata.type, 'bitLocker') or contains(@odata.type, 'fileVault')"
    )
    policies = response.get("value", [])
    
    return {
        "count": len(policies),
        "policies": [
            {
                "id": p.get("id"),
                "displayName": p.get("displayName"),
                "description": p.get("description"),
                "type": p.get("@odata.type", "").replace("#microsoft.graph.", ""),
            }
            for p in policies
        ]
    }


async def get_bitlocker_recovery_keys(device_id: str = None) -> dict[str, Any]:
    """
    Get BitLocker recovery keys.
    
    Args:
        device_id: Optional device ID to filter by
    
    Returns:
        BitLocker recovery key information
    """
    client = get_graph_client()
    
    endpoint = "/informationProtection/bitlocker/recoveryKeys"
    if device_id:
        endpoint += f"?$filter=deviceId eq '{device_id}'"
    
    response = await client.get(endpoint)
    keys = response.get("value", [])
    
    return {
        "count": len(keys),
        "recovery_keys": [
            {
                "id": k.get("id"),
                "createdDateTime": k.get("createdDateTime"),
                "deviceId": k.get("deviceId"),
                "volumeType": k.get("volumeType"),
            }
            for k in keys
        ],
        "note": "Full recovery key values require elevated permissions"
    }


# ============== FIREWALL POLICIES ==============

async def list_firewall_policies() -> dict[str, Any]:
    """
    List Windows Firewall policies.
    
    Returns:
        List of firewall policies
    """
    client = get_graph_client()
    
    response = await client.get(
        "/deviceManagement/deviceConfigurations?$filter=contains(@odata.type, 'firewall')"
    )
    policies = response.get("value", [])
    
    return {
        "count": len(policies),
        "policies": [
            {
                "id": p.get("id"),
                "displayName": p.get("displayName"),
                "description": p.get("description"),
                "type": p.get("@odata.type", "").replace("#microsoft.graph.", ""),
            }
            for p in policies
        ]
    }


# ============== ATTACK SURFACE REDUCTION ==============

async def list_asr_policies() -> dict[str, Any]:
    """
    List Attack Surface Reduction (ASR) policies.
    
    Returns:
        List of ASR policies
    """
    client = get_graph_client()
    
    response = await client.get(
        "/deviceManagement/deviceConfigurations?$filter=contains(@odata.type, 'windows10EndpointProtection')"
    )
    policies = response.get("value", [])
    
    return {
        "count": len(policies),
        "policies": [
            {
                "id": p.get("id"),
                "displayName": p.get("displayName"),
                "description": p.get("description"),
                "type": p.get("@odata.type", "").replace("#microsoft.graph.", ""),
            }
            for p in policies
        ]
    }


# ============== DEFENDER FOR ENDPOINT ==============

async def get_defender_status() -> dict[str, Any]:
    """
    Get Microsoft Defender for Endpoint status across devices.
    
    Returns:
        Defender status summary
    """
    client = get_graph_client()
    
    # Get devices with Defender info
    devices = await client.get(
        "/deviceManagement/managedDevices?$select=deviceName,userPrincipalName,operatingSystem,complianceState&$top=999"
    )
    device_list = devices.get("value", [])
    
    # Try to get Defender-specific status (requires Defender APIs)
    try:
        # This endpoint requires Microsoft Defender for Endpoint license
        machines = await client.get("/security/tiIndicators", use_beta=True)
        has_mde = True
    except:
        has_mde = False
    
    return {
        "total_managed_devices": len(device_list),
        "defender_for_endpoint_available": has_mde,
        "note": "Detailed Defender status requires Microsoft Defender for Endpoint license and additional API permissions"
    }


# ============== ANTIMALWARE REPORTS ==============

async def get_windows_malware_report(top: int = 100) -> dict[str, Any]:
    """
    Get Windows malware information detected across devices.
    
    Args:
        top: Maximum number of malware entries to return
    
    Returns:
        List of detected malware with affected devices
    """
    client = get_graph_client()
    
    try:
        response = await client.get(
            f"/deviceManagement/windowsMalwareInformation?$top={top}&$expand=deviceMalwareStates"
        )
        malware_list = response.get("value", [])
        
        # Categorize by severity
        severity_counts = {"severe": 0, "high": 0, "moderate": 0, "low": 0, "unknown": 0}
        category_counts = {}
        
        malware_details = []
        for m in malware_list:
            severity = m.get("severity", "unknown").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["unknown"] += 1
            
            category = m.get("category", "unknown")
            category_counts[category] = category_counts.get(category, 0) + 1
            
            device_states = m.get("deviceMalwareStates", [])
            
            malware_details.append({
                "id": m.get("id"),
                "displayName": m.get("displayName"),
                "severity": m.get("severity"),
                "category": m.get("category"),
                "additionalInformationUrl": m.get("additionalInformationUrl"),
                "lastDetectionDateTime": m.get("lastDetectionDateTime"),
                "affectedDeviceCount": len(device_states),
                "affectedDevices": [
                    {
                        "deviceName": ds.get("deviceName"),
                        "detectionState": ds.get("detectionState"),
                        "lastStateChangeDateTime": ds.get("lastStateChangeDateTime"),
                        "executionState": ds.get("executionState"),
                    }
                    for ds in device_states[:5]  # Limit to 5 devices per malware
                ]
            })
        
        return {
            "summary": {
                "total_malware_detected": len(malware_list),
                "by_severity": severity_counts,
                "by_category": category_counts
            },
            "malware": malware_details
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Could not retrieve malware information: {str(e)}",
            "note": "This may require DeviceManagementManagedDevices.Read.All permission"
        }


async def get_device_protection_overview() -> dict[str, Any]:
    """
    Get overall device protection status overview.
    
    Returns:
        Protection status summary across all devices
    """
    client = get_graph_client()
    
    try:
        # Try to get protection overview (beta endpoint)
        overview = await client.get(
            "/deviceManagement/deviceProtectionOverview",
            use_beta=True
        )
        
        return {
            "totalReportedDeviceCount": overview.get("totalReportedDeviceCount"),
            "inactiveThreatAgentDeviceCount": overview.get("inactiveThreatAgentDeviceCount"),
            "unknownStateThreatAgentDeviceCount": overview.get("unknownStateThreatAgentDeviceCount"),
            "pendingSignatureUpdateDeviceCount": overview.get("pendingSignatureUpdateDeviceCount"),
            "cleanDeviceCount": overview.get("cleanDeviceCount"),
            "pendingFullScanDeviceCount": overview.get("pendingFullScanDeviceCount"),
            "pendingRestartDeviceCount": overview.get("pendingRestartDeviceCount"),
            "pendingManualStepsDeviceCount": overview.get("pendingManualStepsDeviceCount"),
            "pendingOfflineScanDeviceCount": overview.get("pendingOfflineScanDeviceCount"),
            "criticalFailuresDeviceCount": overview.get("criticalFailuresDeviceCount"),
            "pendingQuickScanDeviceCount": overview.get("pendingQuickScanDeviceCount"),
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Could not retrieve protection overview: {str(e)}"
        }


async def get_device_threat_state(top: int = 100) -> dict[str, Any]:
    """
    Get threat state for all managed Windows devices.
    
    Args:
        top: Maximum number of devices to return
    
    Returns:
        Device threat states
    """
    client = get_graph_client()
    
    try:
        # Get Windows devices with protection state
        response = await client.get(
            f"/deviceManagement/managedDevices?$filter=operatingSystem eq 'Windows'&$select=id,deviceName,userPrincipalName,lastSyncDateTime,complianceState&$top={top}"
        )
        devices = response.get("value", [])
        
        device_threats = []
        threat_counts = {"clean": 0, "fullScanRequired": 0, "rebootRequired": 0, "manualStepsRequired": 0, "offlineScanRequired": 0, "unknown": 0}
        
        for device in devices:
            device_id = device.get("id")
            
            # Try to get protection state for each device
            try:
                protection_state = await client.get(
                    f"/deviceManagement/managedDevices/{device_id}/windowsProtectionState",
                    use_beta=True
                )
                
                threat_status = protection_state.get("deviceProtectionState", "unknown")
                if threat_status in threat_counts:
                    threat_counts[threat_status] += 1
                else:
                    threat_counts["unknown"] += 1
                
                device_threats.append({
                    "deviceName": device.get("deviceName"),
                    "userPrincipalName": device.get("userPrincipalName"),
                    "lastSyncDateTime": device.get("lastSyncDateTime"),
                    "deviceProtectionState": threat_status,
                    "antiMalwareVersion": protection_state.get("antiMalwareVersion"),
                    "engineVersion": protection_state.get("engineVersion"),
                    "signatureVersion": protection_state.get("signatureVersion"),
                    "lastQuickScanDateTime": protection_state.get("lastQuickScanDateTime"),
                    "lastFullScanDateTime": protection_state.get("lastFullScanDateTime"),
                    "lastQuickScanSignatureVersion": protection_state.get("lastQuickScanSignatureVersion"),
                    "lastFullScanSignatureVersion": protection_state.get("lastFullScanSignatureVersion"),
                    "productStatus": protection_state.get("productStatus"),
                    "isVirtualMachine": protection_state.get("isVirtualMachine"),
                    "tamperProtectionEnabled": protection_state.get("tamperProtectionEnabled"),
                })
            except:
                device_threats.append({
                    "deviceName": device.get("deviceName"),
                    "userPrincipalName": device.get("userPrincipalName"),
                    "lastSyncDateTime": device.get("lastSyncDateTime"),
                    "deviceProtectionState": "unknown",
                    "note": "Could not retrieve protection state"
                })
                threat_counts["unknown"] += 1
        
        return {
            "summary": {
                "total_devices": len(devices),
                "by_threat_state": threat_counts
            },
            "devices": device_threats
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Could not retrieve device threat states: {str(e)}"
        }


async def get_detected_malware_on_device(device_id: str) -> dict[str, Any]:
    """
    Get detected malware for a specific device.
    
    Args:
        device_id: The managed device ID
    
    Returns:
        Malware detected on the device
    """
    client = get_graph_client()
    
    try:
        # Get device info
        device = await client.get(
            f"/deviceManagement/managedDevices/{device_id}?$select=deviceName,userPrincipalName"
        )
        
        # Get detected apps (including malware)
        detected = await client.get(
            f"/deviceManagement/managedDevices/{device_id}/detectedApps"
        )
        detected_apps = detected.get("value", [])
        
        # Get protection state
        try:
            protection = await client.get(
                f"/deviceManagement/managedDevices/{device_id}/windowsProtectionState",
                use_beta=True
            )
        except:
            protection = {}
        
        return {
            "device": {
                "deviceName": device.get("deviceName"),
                "userPrincipalName": device.get("userPrincipalName"),
            },
            "protectionState": {
                "deviceProtectionState": protection.get("deviceProtectionState"),
                "antiMalwareVersion": protection.get("antiMalwareVersion"),
                "lastQuickScanDateTime": protection.get("lastQuickScanDateTime"),
                "lastFullScanDateTime": protection.get("lastFullScanDateTime"),
                "malwareProtectionEnabled": protection.get("malwareProtectionEnabled"),
                "networkInspectionSystemEnabled": protection.get("networkInspectionSystemEnabled"),
                "realTimeProtectionEnabled": protection.get("realTimeProtectionEnabled"),
            },
            "detectedApps": [
                {
                    "displayName": app.get("displayName"),
                    "version": app.get("version"),
                    "sizeInByte": app.get("sizeInByte"),
                    "deviceCount": app.get("deviceCount"),
                }
                for app in detected_apps[:50]
            ]
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Could not retrieve malware info for device: {str(e)}"
        }


# ============== APP PROTECTION POLICIES (MAM) ==============

async def list_app_protection_policies() -> dict[str, Any]:
    """
    List mobile app protection policies (MAM).
    
    Returns:
        List of app protection policies
    """
    client = get_graph_client()
    
    # Get iOS policies
    ios_response = await client.get("/deviceAppManagement/iosManagedAppProtections")
    ios_policies = ios_response.get("value", [])
    
    # Get Android policies
    android_response = await client.get("/deviceAppManagement/androidManagedAppProtections")
    android_policies = android_response.get("value", [])
    
    # Get Windows policies
    try:
        windows_response = await client.get("/deviceAppManagement/windowsInformationProtectionPolicies")
        windows_policies = windows_response.get("value", [])
    except:
        windows_policies = []
    
    return {
        "summary": {
            "ios_policies": len(ios_policies),
            "android_policies": len(android_policies),
            "windows_policies": len(windows_policies),
            "total": len(ios_policies) + len(android_policies) + len(windows_policies),
        },
        "ios_policies": [
            {
                "id": p.get("id"),
                "displayName": p.get("displayName"),
                "description": p.get("description"),
            }
            for p in ios_policies
        ],
        "android_policies": [
            {
                "id": p.get("id"),
                "displayName": p.get("displayName"),
                "description": p.get("description"),
            }
            for p in android_policies
        ],
        "windows_policies": [
            {
                "id": p.get("id"),
                "displayName": p.get("displayName"),
                "description": p.get("description"),
            }
            for p in windows_policies
        ],
    }


async def get_app_protection_policy(policy_id: str, platform: str) -> dict[str, Any]:
    """
    Get detailed information about an app protection policy.
    
    Args:
        policy_id: The policy ID
        platform: "ios" or "android"
    
    Returns:
        Policy details
    """
    client = get_graph_client()
    
    if platform.lower() == "ios":
        endpoint = f"/deviceAppManagement/iosManagedAppProtections/{policy_id}"
    elif platform.lower() == "android":
        endpoint = f"/deviceAppManagement/androidManagedAppProtections/{policy_id}"
    else:
        return {"error": "Invalid platform. Use 'ios' or 'android'"}
    
    policy = await client.get(endpoint)
    
    return {
        "id": policy.get("id"),
        "displayName": policy.get("displayName"),
        "description": policy.get("description"),
        "version": policy.get("version"),
        "createdDateTime": policy.get("createdDateTime"),
        "lastModifiedDateTime": policy.get("lastModifiedDateTime"),
        "periodOfflineBeforeAccessCheck": policy.get("periodOfflineBeforeAccessCheck"),
        "periodOnlineBeforeAccessCheck": policy.get("periodOnlineBeforeAccessCheck"),
        "allowedInboundDataTransferSources": policy.get("allowedInboundDataTransferSources"),
        "allowedOutboundDataTransferDestinations": policy.get("allowedOutboundDataTransferDestinations"),
        "organizationalCredentialsRequired": policy.get("organizationalCredentialsRequired"),
        "allowedOutboundClipboardSharingLevel": policy.get("allowedOutboundClipboardSharingLevel"),
        "dataBackupBlocked": policy.get("dataBackupBlocked"),
        "deviceComplianceRequired": policy.get("deviceComplianceRequired"),
        "managedBrowserToOpenLinksRequired": policy.get("managedBrowserToOpenLinksRequired"),
        "saveAsBlocked": policy.get("saveAsBlocked"),
        "periodOfflineBeforeWipeIsEnforced": policy.get("periodOfflineBeforeWipeIsEnforced"),
        "pinRequired": policy.get("pinRequired"),
        "pinCharacterSet": policy.get("pinCharacterSet"),
        "minimumPinLength": policy.get("minimumPinLength"),
        "fingerprintBlocked": policy.get("fingerprintBlocked"),
        "disableAppPinIfDevicePinIsSet": policy.get("disableAppPinIfDevicePinIsSet"),
    }


async def get_app_protection_status() -> dict[str, Any]:
    """
    Get app protection status summary.
    
    Returns:
        App protection status across users
    """
    client = get_graph_client()
    
    try:
        # Get managed app registrations
        registrations = await client.get(
            "/deviceAppManagement/managedAppRegistrations?$top=100"
        )
        reg_list = registrations.get("value", [])
        
        # Count by platform and status
        platform_counts = {}
        for reg in reg_list:
            platform = reg.get("deviceType", "unknown")
            platform_counts[platform] = platform_counts.get(platform, 0) + 1
        
        return {
            "total_app_registrations": len(reg_list),
            "by_platform": platform_counts,
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Could not retrieve app protection status: {str(e)}"
        }


# ============== ENROLLMENT RESTRICTIONS ==============

async def list_enrollment_restrictions() -> dict[str, Any]:
    """
    List device enrollment restrictions.
    
    Returns:
        List of enrollment restriction policies
    """
    client = get_graph_client()
    
    response = await client.get("/deviceManagement/deviceEnrollmentConfigurations")
    configs = response.get("value", [])
    
    return {
        "count": len(configs),
        "restrictions": [
            {
                "id": c.get("id"),
                "displayName": c.get("displayName"),
                "description": c.get("description"),
                "type": c.get("@odata.type", "").replace("#microsoft.graph.", ""),
                "priority": c.get("priority"),
                "createdDateTime": c.get("createdDateTime"),
                "lastModifiedDateTime": c.get("lastModifiedDateTime"),
            }
            for c in configs
        ]
    }


async def get_enrollment_restriction(config_id: str) -> dict[str, Any]:
    """
    Get details of an enrollment restriction.
    
    Args:
        config_id: The configuration ID
    
    Returns:
        Enrollment restriction details
    """
    client = get_graph_client()
    
    config = await client.get(f"/deviceManagement/deviceEnrollmentConfigurations/{config_id}")
    
    return {
        "id": config.get("id"),
        "displayName": config.get("displayName"),
        "description": config.get("description"),
        "type": config.get("@odata.type", "").replace("#microsoft.graph.", ""),
        "priority": config.get("priority"),
        "platformRestrictions": config.get("platformRestrictions"),
        "createdDateTime": config.get("createdDateTime"),
        "lastModifiedDateTime": config.get("lastModifiedDateTime"),
    }


# ============== DEVICE CATEGORIES ==============

async def list_device_categories() -> dict[str, Any]:
    """
    List all device categories.
    
    Returns:
        List of device categories
    """
    client = get_graph_client()
    
    response = await client.get("/deviceManagement/deviceCategories")
    categories = response.get("value", [])
    
    return {
        "count": len(categories),
        "categories": [
            {
                "id": c.get("id"),
                "displayName": c.get("displayName"),
                "description": c.get("description"),
            }
            for c in categories
        ]
    }


async def create_device_category(display_name: str, description: str = "") -> dict[str, Any]:
    """
    Create a new device category.
    
    Args:
        display_name: Category name
        description: Category description
    
    Returns:
        Created category details
    """
    client = get_graph_client()
    
    result = await client.post(
        "/deviceManagement/deviceCategories",
        json={
            "displayName": display_name,
            "description": description
        }
    )
    
    return {
        "status": "success",
        "message": f"Device category '{display_name}' created",
        "category": {
            "id": result.get("id"),
            "displayName": result.get("displayName"),
        }
    }


async def delete_device_category(category_id: str, confirm: bool = False) -> dict[str, Any]:
    """
    Delete a device category.
    
    Args:
        category_id: The category ID
        confirm: Must be True to execute
    
    Returns:
        Deletion status
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "⚠️ DELETE will remove the device category! Set confirm=True to proceed."
        }
    
    client = get_graph_client()
    
    category = await client.get(f"/deviceManagement/deviceCategories/{category_id}")
    
    await client.delete(f"/deviceManagement/deviceCategories/{category_id}")
    
    return {
        "status": "success",
        "message": f"Device category '{category.get('displayName')}' deleted"
    }

