"""
Windows 365 Cloud PC Management Tools
Manage Cloud PCs, provisioning policies, and user settings.
"""

from typing import Any
from ..graph_client import get_graph_client


# ============== CLOUD PC MANAGEMENT ==============

async def list_cloud_pcs(top: int = 50, filter_query: str = "") -> dict[str, Any]:
    """
    List all Cloud PCs in the tenant.
    
    Args:
        top: Maximum number of Cloud PCs to return
        filter_query: OData filter query
    
    Returns:
        List of Cloud PCs with their status
    """
    client = get_graph_client()
    
    endpoint = f"/deviceManagement/virtualEndpoint/cloudPCs?$top={top}"
    if filter_query:
        endpoint += f"&$filter={filter_query}"
    
    response = await client.get(endpoint, use_beta=True)
    cloud_pcs = response.get("value", [])
    
    return {
        "count": len(cloud_pcs),
        "cloud_pcs": [
            {
                "id": pc.get("id"),
                "displayName": pc.get("displayName"),
                "managedDeviceId": pc.get("managedDeviceId"),
                "managedDeviceName": pc.get("managedDeviceName"),
                "userPrincipalName": pc.get("userPrincipalName"),
                "provisioningPolicyId": pc.get("provisioningPolicyId"),
                "provisioningPolicyName": pc.get("provisioningPolicyName"),
                "status": pc.get("status"),
                "statusDetails": pc.get("statusDetails"),
                "gracePeriodEndDateTime": pc.get("gracePeriodEndDateTime"),
                "imageDisplayName": pc.get("imageDisplayName"),
                "lastModifiedDateTime": pc.get("lastModifiedDateTime"),
            }
            for pc in cloud_pcs
        ]
    }


async def get_cloud_pc_details(cloud_pc_id: str) -> dict[str, Any]:
    """
    Get detailed information about a specific Cloud PC.
    
    Args:
        cloud_pc_id: The Cloud PC ID
    
    Returns:
        Detailed Cloud PC information
    """
    client = get_graph_client()
    
    pc = await client.get(f"/deviceManagement/virtualEndpoint/cloudPCs/{cloud_pc_id}", use_beta=True)
    
    return {
        "id": pc.get("id"),
        "displayName": pc.get("displayName"),
        "managedDeviceId": pc.get("managedDeviceId"),
        "managedDeviceName": pc.get("managedDeviceName"),
        "userPrincipalName": pc.get("userPrincipalName"),
        "servicePlanId": pc.get("servicePlanId"),
        "servicePlanName": pc.get("servicePlanName"),
        "provisioningPolicyId": pc.get("provisioningPolicyId"),
        "provisioningPolicyName": pc.get("provisioningPolicyName"),
        "onPremisesConnectionName": pc.get("onPremisesConnectionName"),
        "status": pc.get("status"),
        "statusDetails": pc.get("statusDetails"),
        "aadDeviceId": pc.get("aadDeviceId"),
        "imageDisplayName": pc.get("imageDisplayName"),
        "gracePeriodEndDateTime": pc.get("gracePeriodEndDateTime"),
        "lastModifiedDateTime": pc.get("lastModifiedDateTime"),
        "lastLoginResult": pc.get("lastLoginResult"),
        "lastRemoteActionResult": pc.get("lastRemoteActionResult"),
    }


async def reprovision_cloud_pc(cloud_pc_id: str, confirm: bool = False) -> dict[str, Any]:
    """
    Reprovision a Cloud PC. This will reset it to its original state.
    
    Args:
        cloud_pc_id: The Cloud PC ID
        confirm: Must be True to execute
    
    Returns:
        Status of the operation
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "⚠️ REPROVISION will reset the Cloud PC! All data will be lost. Set confirm=True to proceed."
        }
    
    client = get_graph_client()
    
    pc = await client.get(f"/deviceManagement/virtualEndpoint/cloudPCs/{cloud_pc_id}", use_beta=True)
    
    await client.post(
        f"/deviceManagement/virtualEndpoint/cloudPCs/{cloud_pc_id}/reprovision",
        use_beta=True
    )
    
    return {
        "status": "success",
        "message": f"Reprovision initiated for Cloud PC '{pc.get('displayName')}'",
        "cloud_pc_id": cloud_pc_id
    }


async def restart_cloud_pc(cloud_pc_id: str) -> dict[str, Any]:
    """
    Restart a Cloud PC.
    
    Args:
        cloud_pc_id: The Cloud PC ID
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    pc = await client.get(f"/deviceManagement/virtualEndpoint/cloudPCs/{cloud_pc_id}", use_beta=True)
    
    await client.post(
        f"/deviceManagement/virtualEndpoint/cloudPCs/{cloud_pc_id}/reboot",
        use_beta=True
    )
    
    return {
        "status": "success",
        "message": f"Restart initiated for Cloud PC '{pc.get('displayName')}'",
        "cloud_pc_id": cloud_pc_id
    }


async def rename_cloud_pc(cloud_pc_id: str, new_name: str) -> dict[str, Any]:
    """
    Rename a Cloud PC.
    
    Args:
        cloud_pc_id: The Cloud PC ID
        new_name: The new display name
    
    Returns:
        Status of the operation
    """
    client = get_graph_client()
    
    pc = await client.get(f"/deviceManagement/virtualEndpoint/cloudPCs/{cloud_pc_id}", use_beta=True)
    old_name = pc.get("displayName")
    
    await client.post(
        f"/deviceManagement/virtualEndpoint/cloudPCs/{cloud_pc_id}/rename",
        json={"displayName": new_name},
        use_beta=True
    )
    
    return {
        "status": "success",
        "message": f"Cloud PC renamed from '{old_name}' to '{new_name}'",
        "cloud_pc_id": cloud_pc_id
    }


async def get_cloud_pc_launch_info(cloud_pc_id: str) -> dict[str, Any]:
    """
    Get the launch information (connection URL) for a Cloud PC.
    
    Args:
        cloud_pc_id: The Cloud PC ID
    
    Returns:
        Launch URL and connection details
    """
    client = get_graph_client()
    
    result = await client.get(
        f"/deviceManagement/virtualEndpoint/cloudPCs/{cloud_pc_id}/getCloudPcLaunchInfo",
        use_beta=True
    )
    
    return {
        "cloudPcLaunchUrl": result.get("cloudPcLaunchUrl"),
        "windows365WebLaunchUrl": result.get("windows365WebLaunchUrl"),
    }


async def end_grace_period(cloud_pc_id: str, confirm: bool = False) -> dict[str, Any]:
    """
    End the grace period for a Cloud PC (will be deprovisioned).
    
    Args:
        cloud_pc_id: The Cloud PC ID
        confirm: Must be True to execute
    
    Returns:
        Status of the operation
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "⚠️ This will end the grace period and deprovision the Cloud PC! Set confirm=True to proceed."
        }
    
    client = get_graph_client()
    
    await client.post(
        f"/deviceManagement/virtualEndpoint/cloudPCs/{cloud_pc_id}/endGracePeriod",
        use_beta=True
    )
    
    return {
        "status": "success",
        "message": f"Grace period ended for Cloud PC {cloud_pc_id}",
    }


# ============== CLOUD PC RESTORE POINTS ==============

async def get_cloud_pc_restore_points(cloud_pc_id: str) -> dict[str, Any]:
    """
    Get available restore points for a Cloud PC.
    
    Args:
        cloud_pc_id: The Cloud PC ID
    
    Returns:
        List of available restore points
    """
    client = get_graph_client()
    
    response = await client.get(
        f"/deviceManagement/virtualEndpoint/cloudPCs/{cloud_pc_id}/getCloudPcRestorePoints",
        use_beta=True
    )
    
    restore_points = response.get("value", [])
    
    return {
        "cloud_pc_id": cloud_pc_id,
        "count": len(restore_points),
        "restore_points": restore_points
    }


async def restore_cloud_pc(
    cloud_pc_id: str,
    restore_point_id: str,
    confirm: bool = False
) -> dict[str, Any]:
    """
    Restore a Cloud PC to a previous point in time.
    
    Args:
        cloud_pc_id: The Cloud PC ID
        restore_point_id: The restore point ID
        confirm: Must be True to execute
    
    Returns:
        Status of the operation
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "⚠️ This will restore the Cloud PC to a previous state! Set confirm=True to proceed."
        }
    
    client = get_graph_client()
    
    await client.post(
        f"/deviceManagement/virtualEndpoint/cloudPCs/{cloud_pc_id}/restore",
        json={"cloudPcSnapshotId": restore_point_id},
        use_beta=True
    )
    
    return {
        "status": "success",
        "message": f"Restore initiated for Cloud PC {cloud_pc_id}",
        "restore_point_id": restore_point_id
    }


# ============== PROVISIONING POLICIES ==============

async def list_provisioning_policies() -> dict[str, Any]:
    """
    List all Cloud PC provisioning policies.
    
    Returns:
        List of provisioning policies
    """
    client = get_graph_client()
    
    response = await client.get(
        "/deviceManagement/virtualEndpoint/provisioningPolicies",
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
                "provisioningType": p.get("provisioningType"),
                "imageId": p.get("imageId"),
                "imageDisplayName": p.get("imageDisplayName"),
                "imageType": p.get("imageType"),
                "enableSingleSignOn": p.get("enableSingleSignOn"),
                "domainJoinConfiguration": p.get("domainJoinConfiguration"),
                "windowsSettings": p.get("windowsSettings"),
            }
            for p in policies
        ]
    }


async def get_provisioning_policy(policy_id: str) -> dict[str, Any]:
    """
    Get details of a specific provisioning policy.
    
    Args:
        policy_id: The policy ID
    
    Returns:
        Provisioning policy details
    """
    client = get_graph_client()
    
    policy = await client.get(
        f"/deviceManagement/virtualEndpoint/provisioningPolicies/{policy_id}",
        use_beta=True
    )
    
    # Get assignments
    try:
        assignments = await client.get(
            f"/deviceManagement/virtualEndpoint/provisioningPolicies/{policy_id}/assignments",
            use_beta=True
        )
        assignment_list = assignments.get("value", [])
    except:
        assignment_list = []
    
    return {
        "policy": policy,
        "assignments": assignment_list
    }


async def create_provisioning_policy(
    display_name: str,
    description: str = "",
    image_id: str = None,
    image_type: str = "gallery",
    enable_single_sign_on: bool = True,
    local_admin_enabled: bool = False
) -> dict[str, Any]:
    """
    Create a new Cloud PC provisioning policy.
    
    Args:
        display_name: Policy name
        description: Policy description
        image_id: Image ID to use
        image_type: "gallery" or "custom"
        enable_single_sign_on: Enable SSO
        local_admin_enabled: Make users local admins
    
    Returns:
        Created policy details
    """
    client = get_graph_client()
    
    policy_data = {
        "displayName": display_name,
        "description": description,
        "imageType": image_type,
        "enableSingleSignOn": enable_single_sign_on,
        "windowsSettings": {
            "language": "en-US"
        },
        "domainJoinConfiguration": {
            "type": "azureADJoin"
        }
    }
    
    if image_id:
        policy_data["imageId"] = image_id
    
    if local_admin_enabled:
        policy_data["localAdminEnabled"] = local_admin_enabled
    
    result = await client.post(
        "/deviceManagement/virtualEndpoint/provisioningPolicies",
        json=policy_data,
        use_beta=True
    )
    
    return {
        "status": "success",
        "message": f"Provisioning policy '{display_name}' created",
        "policy": {
            "id": result.get("id"),
            "displayName": result.get("displayName"),
        }
    }


async def assign_provisioning_policy(
    policy_id: str,
    group_ids: list
) -> dict[str, Any]:
    """
    Assign a provisioning policy to groups.
    
    Args:
        policy_id: The policy ID
        group_ids: List of group IDs to assign
    
    Returns:
        Status of the assignment
    """
    client = get_graph_client()
    
    assignments = [
        {
            "target": {
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": gid
            }
        }
        for gid in group_ids
    ]
    
    await client.post(
        f"/deviceManagement/virtualEndpoint/provisioningPolicies/{policy_id}/assign",
        json={"assignments": assignments},
        use_beta=True
    )
    
    return {
        "status": "success",
        "message": f"Policy assigned to {len(group_ids)} group(s)"
    }


async def delete_provisioning_policy(policy_id: str, confirm: bool = False) -> dict[str, Any]:
    """
    Delete a provisioning policy.
    
    Args:
        policy_id: The policy ID
        confirm: Must be True to execute
    
    Returns:
        Deletion status
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "⚠️ DELETE will remove the provisioning policy! Set confirm=True to proceed."
        }
    
    client = get_graph_client()
    
    policy = await client.get(
        f"/deviceManagement/virtualEndpoint/provisioningPolicies/{policy_id}",
        use_beta=True
    )
    
    await client.delete(
        f"/deviceManagement/virtualEndpoint/provisioningPolicies/{policy_id}",
        use_beta=True
    )
    
    return {
        "status": "success",
        "message": f"Provisioning policy '{policy.get('displayName')}' deleted"
    }


# ============== GALLERY IMAGES ==============

async def list_gallery_images() -> dict[str, Any]:
    """
    List available gallery images for Cloud PC provisioning.
    
    Returns:
        List of gallery images
    """
    client = get_graph_client()
    
    response = await client.get(
        "/deviceManagement/virtualEndpoint/galleryImages",
        use_beta=True
    )
    images = response.get("value", [])
    
    return {
        "count": len(images),
        "images": [
            {
                "id": img.get("id"),
                "displayName": img.get("displayName"),
                "offerDisplayName": img.get("offerDisplayName"),
                "skuDisplayName": img.get("skuDisplayName"),
                "publisherName": img.get("publisherName"),
                "version": img.get("version"),
                "startDate": img.get("startDate"),
                "endDate": img.get("endDate"),
                "status": img.get("status"),
            }
            for img in images
        ]
    }


# ============== DEVICE IMAGES (CUSTOM) ==============

async def list_device_images() -> dict[str, Any]:
    """
    List custom device images for Cloud PC provisioning.
    
    Returns:
        List of custom device images
    """
    client = get_graph_client()
    
    response = await client.get(
        "/deviceManagement/virtualEndpoint/deviceImages",
        use_beta=True
    )
    images = response.get("value", [])
    
    return {
        "count": len(images),
        "images": [
            {
                "id": img.get("id"),
                "displayName": img.get("displayName"),
                "status": img.get("status"),
                "statusDetails": img.get("statusDetails"),
                "sourceImageResourceId": img.get("sourceImageResourceId"),
                "operatingSystem": img.get("operatingSystem"),
                "osBuildNumber": img.get("osBuildNumber"),
                "osStatus": img.get("osStatus"),
                "version": img.get("version"),
                "lastModifiedDateTime": img.get("lastModifiedDateTime"),
            }
            for img in images
        ]
    }


# ============== ON-PREMISES CONNECTIONS ==============

async def list_on_premises_connections() -> dict[str, Any]:
    """
    List Azure network connections for Cloud PC.
    
    Returns:
        List of on-premises connections
    """
    client = get_graph_client()
    
    response = await client.get(
        "/deviceManagement/virtualEndpoint/onPremisesConnections",
        use_beta=True
    )
    connections = response.get("value", [])
    
    return {
        "count": len(connections),
        "connections": [
            {
                "id": c.get("id"),
                "displayName": c.get("displayName"),
                "subscriptionId": c.get("subscriptionId"),
                "subscriptionName": c.get("subscriptionName"),
                "resourceGroupId": c.get("resourceGroupId"),
                "virtualNetworkId": c.get("virtualNetworkId"),
                "virtualNetworkLocation": c.get("virtualNetworkLocation"),
                "subnetId": c.get("subnetId"),
                "healthCheckStatus": c.get("healthCheckStatus"),
                "healthCheckStatusDetails": c.get("healthCheckStatusDetails"),
            }
            for c in connections
        ]
    }


async def run_health_check(connection_id: str) -> dict[str, Any]:
    """
    Run a health check on an on-premises connection.
    
    Args:
        connection_id: The connection ID
    
    Returns:
        Status of the health check
    """
    client = get_graph_client()
    
    await client.post(
        f"/deviceManagement/virtualEndpoint/onPremisesConnections/{connection_id}/runHealthChecks",
        use_beta=True
    )
    
    return {
        "status": "success",
        "message": f"Health check initiated for connection {connection_id}"
    }


# ============== USER SETTINGS ==============

async def list_user_settings() -> dict[str, Any]:
    """
    List Cloud PC user settings policies.
    
    Returns:
        List of user settings
    """
    client = get_graph_client()
    
    response = await client.get(
        "/deviceManagement/virtualEndpoint/userSettings",
        use_beta=True
    )
    settings = response.get("value", [])
    
    return {
        "count": len(settings),
        "settings": [
            {
                "id": s.get("id"),
                "displayName": s.get("displayName"),
                "selfServiceEnabled": s.get("selfServiceEnabled"),
                "localAdminEnabled": s.get("localAdminEnabled"),
                "restorePointSetting": s.get("restorePointSetting"),
                "lastModifiedDateTime": s.get("lastModifiedDateTime"),
            }
            for s in settings
        ]
    }


async def create_user_settings(
    display_name: str,
    self_service_enabled: bool = True,
    local_admin_enabled: bool = False,
    restore_point_frequency_type: str = "sixHours"
) -> dict[str, Any]:
    """
    Create a new Cloud PC user settings policy.
    
    Args:
        display_name: Settings name
        self_service_enabled: Allow users to restart/troubleshoot
        local_admin_enabled: Make users local admins
        restore_point_frequency_type: "fourHours", "sixHours", "twelveHours", "twentyFourHours"
    
    Returns:
        Created settings details
    """
    client = get_graph_client()
    
    settings_data = {
        "displayName": display_name,
        "selfServiceEnabled": self_service_enabled,
        "localAdminEnabled": local_admin_enabled,
        "restorePointSetting": {
            "frequencyType": restore_point_frequency_type,
            "userRestoreEnabled": True
        }
    }
    
    result = await client.post(
        "/deviceManagement/virtualEndpoint/userSettings",
        json=settings_data,
        use_beta=True
    )
    
    return {
        "status": "success",
        "message": f"User settings '{display_name}' created",
        "settings": {
            "id": result.get("id"),
            "displayName": result.get("displayName"),
        }
    }


# ============== CLOUD PC REPORTS ==============

async def get_cloud_pc_overview() -> dict[str, Any]:
    """
    Get an overview of all Cloud PCs in the tenant.
    
    Returns:
        Cloud PC statistics and summary
    """
    client = get_graph_client()
    
    cloud_pcs = await client.get(
        "/deviceManagement/virtualEndpoint/cloudPCs?$top=999",
        use_beta=True
    )
    pc_list = cloud_pcs.get("value", [])
    
    # Count by status
    status_counts = {}
    provisioning_policy_counts = {}
    
    for pc in pc_list:
        status = pc.get("status", "unknown")
        policy = pc.get("provisioningPolicyName", "Unknown")
        
        status_counts[status] = status_counts.get(status, 0) + 1
        provisioning_policy_counts[policy] = provisioning_policy_counts.get(policy, 0) + 1
    
    return {
        "summary": {
            "total_cloud_pcs": len(pc_list),
            "provisioned": status_counts.get("provisioned", 0),
            "provisioning": status_counts.get("provisioning", 0),
            "failed": status_counts.get("failed", 0),
            "in_grace_period": status_counts.get("inGracePeriod", 0),
        },
        "by_status": status_counts,
        "by_provisioning_policy": provisioning_policy_counts,
    }

