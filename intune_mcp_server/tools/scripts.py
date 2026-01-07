"""
Intune Scripts and Remediations Tools
PowerShell scripts, proactive remediations, and custom actions.
"""

from typing import Any
from ..graph_client import get_graph_client


# ============== POWERSHELL SCRIPTS ==============

async def list_device_management_scripts(top: int = 50) -> dict[str, Any]:
    """
    List all PowerShell scripts deployed through Intune.
    
    Args:
        top: Maximum number of scripts to return
    
    Returns:
        List of device management scripts
    """
    client = get_graph_client()
    
    response = await client.get(f"/deviceManagement/deviceManagementScripts?$top={top}")
    scripts = response.get("value", [])
    
    return {
        "count": len(scripts),
        "scripts": [
            {
                "id": s.get("id"),
                "displayName": s.get("displayName"),
                "description": s.get("description"),
                "runAsAccount": s.get("runAsAccount"),
                "enforceSignatureCheck": s.get("enforceSignatureCheck"),
                "runAs32Bit": s.get("runAs32Bit"),
                "fileName": s.get("fileName"),
                "createdDateTime": s.get("createdDateTime"),
                "lastModifiedDateTime": s.get("lastModifiedDateTime"),
            }
            for s in scripts
        ]
    }


async def get_device_management_script(script_id: str) -> dict[str, Any]:
    """
    Get details of a specific PowerShell script including the script content.
    
    Args:
        script_id: The script ID
    
    Returns:
        Script details and content
    """
    client = get_graph_client()
    
    script = await client.get(f"/deviceManagement/deviceManagementScripts/{script_id}")
    
    # Get assignments
    try:
        assignments = await client.get(
            f"/deviceManagement/deviceManagementScripts/{script_id}/assignments"
        )
        assignment_list = assignments.get("value", [])
    except:
        assignment_list = []
    
    # Get device run states
    try:
        states = await client.get(
            f"/deviceManagement/deviceManagementScripts/{script_id}/deviceRunStates?$top=50"
        )
        run_states = states.get("value", [])
    except:
        run_states = []
    
    # Decode script content if present
    script_content = script.get("scriptContent")
    if script_content:
        import base64
        try:
            decoded_content = base64.b64decode(script_content).decode('utf-8')
        except:
            decoded_content = "[Unable to decode script content]"
    else:
        decoded_content = None
    
    return {
        "id": script.get("id"),
        "displayName": script.get("displayName"),
        "description": script.get("description"),
        "runAsAccount": script.get("runAsAccount"),
        "enforceSignatureCheck": script.get("enforceSignatureCheck"),
        "runAs32Bit": script.get("runAs32Bit"),
        "fileName": script.get("fileName"),
        "scriptContent": decoded_content,
        "createdDateTime": script.get("createdDateTime"),
        "lastModifiedDateTime": script.get("lastModifiedDateTime"),
        "assignments": assignment_list,
        "recent_run_states": [
            {
                "deviceName": rs.get("managedDevice", {}).get("deviceName"),
                "lastStateUpdateDateTime": rs.get("lastStateUpdateDateTime"),
                "resultMessage": rs.get("resultMessage"),
                "runState": rs.get("runState"),
                "errorCode": rs.get("errorCode"),
            }
            for rs in run_states[:10]
        ]
    }


async def get_script_device_status(script_id: str, top: int = 100) -> dict[str, Any]:
    """
    Get the deployment status of a script across devices.
    
    Args:
        script_id: The script ID
        top: Maximum number of statuses to return
    
    Returns:
        Script deployment status by device
    """
    client = get_graph_client()
    
    script = await client.get(f"/deviceManagement/deviceManagementScripts/{script_id}?$select=displayName")
    
    states = await client.get(
        f"/deviceManagement/deviceManagementScripts/{script_id}/deviceRunStates?$expand=managedDevice&$top={top}"
    )
    run_states = states.get("value", [])
    
    # Count by state
    state_counts = {}
    for rs in run_states:
        state = rs.get("runState", "unknown")
        state_counts[state] = state_counts.get(state, 0) + 1
    
    return {
        "script": {
            "id": script_id,
            "displayName": script.get("displayName"),
        },
        "summary": {
            "total_devices": len(run_states),
            "by_state": state_counts,
        },
        "device_states": [
            {
                "deviceName": rs.get("managedDevice", {}).get("deviceName"),
                "userPrincipalName": rs.get("managedDevice", {}).get("userPrincipalName"),
                "runState": rs.get("runState"),
                "resultMessage": rs.get("resultMessage"),
                "lastStateUpdateDateTime": rs.get("lastStateUpdateDateTime"),
                "errorCode": rs.get("errorCode"),
                "errorDescription": rs.get("errorDescription"),
            }
            for rs in run_states
        ]
    }


async def create_device_management_script(
    display_name: str,
    script_content: str,
    description: str = "",
    run_as_account: str = "system",
    enforce_signature_check: bool = False,
    run_as_32_bit: bool = False,
    file_name: str = "script.ps1"
) -> dict[str, Any]:
    """
    Create a new PowerShell script for deployment.
    
    Args:
        display_name: Script name
        script_content: The PowerShell script content
        description: Script description
        run_as_account: "system" or "user"
        enforce_signature_check: Require script signing
        run_as_32_bit: Run in 32-bit PowerShell
        file_name: Script file name
    
    Returns:
        Created script details
    """
    client = get_graph_client()
    
    import base64
    encoded_content = base64.b64encode(script_content.encode('utf-8')).decode('utf-8')
    
    script_data = {
        "displayName": display_name,
        "description": description,
        "scriptContent": encoded_content,
        "runAsAccount": run_as_account,
        "enforceSignatureCheck": enforce_signature_check,
        "runAs32Bit": run_as_32_bit,
        "fileName": file_name,
    }
    
    result = await client.post("/deviceManagement/deviceManagementScripts", json=script_data)
    
    return {
        "status": "success",
        "message": f"Script '{display_name}' created",
        "script": {
            "id": result.get("id"),
            "displayName": result.get("displayName"),
        }
    }


async def assign_script(script_id: str, group_ids: list) -> dict[str, Any]:
    """
    Assign a script to groups.
    
    Args:
        script_id: The script ID
        group_ids: List of group IDs to assign
    
    Returns:
        Status of the assignment
    """
    client = get_graph_client()
    
    script = await client.get(f"/deviceManagement/deviceManagementScripts/{script_id}?$select=displayName")
    
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
        f"/deviceManagement/deviceManagementScripts/{script_id}/assign",
        json={"deviceManagementScriptAssignments": assignments}
    )
    
    return {
        "status": "success",
        "message": f"Script '{script.get('displayName')}' assigned to {len(group_ids)} group(s)"
    }


async def delete_device_management_script(script_id: str, confirm: bool = False) -> dict[str, Any]:
    """
    Delete a PowerShell script.
    
    Args:
        script_id: The script ID
        confirm: Must be True to execute
    
    Returns:
        Deletion status
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "⚠️ DELETE will remove the script! Set confirm=True to proceed."
        }
    
    client = get_graph_client()
    
    script = await client.get(f"/deviceManagement/deviceManagementScripts/{script_id}?$select=displayName")
    
    await client.delete(f"/deviceManagement/deviceManagementScripts/{script_id}")
    
    return {
        "status": "success",
        "message": f"Script '{script.get('displayName')}' deleted"
    }


# ============== PROACTIVE REMEDIATIONS ==============

async def list_device_health_scripts(top: int = 50) -> dict[str, Any]:
    """
    List all proactive remediation scripts (device health scripts).
    
    Args:
        top: Maximum number of scripts to return
    
    Returns:
        List of proactive remediation scripts
    """
    client = get_graph_client()
    
    response = await client.get(
        f"/deviceManagement/deviceHealthScripts?$top={top}",
        use_beta=True
    )
    scripts = response.get("value", [])
    
    return {
        "count": len(scripts),
        "scripts": [
            {
                "id": s.get("id"),
                "displayName": s.get("displayName"),
                "description": s.get("description"),
                "publisher": s.get("publisher"),
                "runAsAccount": s.get("runAsAccount"),
                "runAs32Bit": s.get("runAs32Bit"),
                "enforceSignatureCheck": s.get("enforceSignatureCheck"),
                "isGlobalScript": s.get("isGlobalScript"),
                "createdDateTime": s.get("createdDateTime"),
                "lastModifiedDateTime": s.get("lastModifiedDateTime"),
            }
            for s in scripts
        ]
    }


async def get_device_health_script(script_id: str) -> dict[str, Any]:
    """
    Get details of a proactive remediation script.
    
    Args:
        script_id: The script ID
    
    Returns:
        Script details including detection and remediation scripts
    """
    client = get_graph_client()
    
    script = await client.get(
        f"/deviceManagement/deviceHealthScripts/{script_id}",
        use_beta=True
    )
    
    # Decode scripts
    import base64
    
    detection_content = script.get("detectionScriptContent")
    if detection_content:
        try:
            detection_decoded = base64.b64decode(detection_content).decode('utf-8')
        except:
            detection_decoded = "[Unable to decode]"
    else:
        detection_decoded = None
    
    remediation_content = script.get("remediationScriptContent")
    if remediation_content:
        try:
            remediation_decoded = base64.b64decode(remediation_content).decode('utf-8')
        except:
            remediation_decoded = "[Unable to decode]"
    else:
        remediation_decoded = None
    
    return {
        "id": script.get("id"),
        "displayName": script.get("displayName"),
        "description": script.get("description"),
        "publisher": script.get("publisher"),
        "runAsAccount": script.get("runAsAccount"),
        "runAs32Bit": script.get("runAs32Bit"),
        "enforceSignatureCheck": script.get("enforceSignatureCheck"),
        "isGlobalScript": script.get("isGlobalScript"),
        "detectionScriptContent": detection_decoded,
        "remediationScriptContent": remediation_decoded,
        "createdDateTime": script.get("createdDateTime"),
        "lastModifiedDateTime": script.get("lastModifiedDateTime"),
    }


async def get_device_health_script_status(script_id: str) -> dict[str, Any]:
    """
    Get the status summary for a proactive remediation script.
    
    Args:
        script_id: The script ID
    
    Returns:
        Status summary including detection and remediation results
    """
    client = get_graph_client()
    
    script = await client.get(
        f"/deviceManagement/deviceHealthScripts/{script_id}?$select=displayName",
        use_beta=True
    )
    
    # Get run summary
    try:
        summary = await client.get(
            f"/deviceManagement/deviceHealthScripts/{script_id}/runSummary",
            use_beta=True
        )
    except:
        summary = {}
    
    # Get device run states
    try:
        states = await client.get(
            f"/deviceManagement/deviceHealthScripts/{script_id}/deviceRunStates?$top=50",
            use_beta=True
        )
        run_states = states.get("value", [])
    except:
        run_states = []
    
    return {
        "script": {
            "id": script_id,
            "displayName": script.get("displayName"),
        },
        "summary": {
            "detectionScriptNotApplicableDeviceCount": summary.get("detectionScriptNotApplicableDeviceCount"),
            "detectionScriptPendingDeviceCount": summary.get("detectionScriptPendingDeviceCount"),
            "detectionScriptErrorDeviceCount": summary.get("detectionScriptErrorDeviceCount"),
            "issueDetectedDeviceCount": summary.get("issueDetectedDeviceCount"),
            "noIssueDetectedDeviceCount": summary.get("noIssueDetectedDeviceCount"),
            "remediationScriptErrorDeviceCount": summary.get("remediationScriptErrorDeviceCount"),
            "remediationSuccessDeviceCount": summary.get("remediationSuccessDeviceCount"),
            "lastScriptRunDateTime": summary.get("lastScriptRunDateTime"),
        },
        "recent_device_states": [
            {
                "managedDeviceId": rs.get("managedDeviceId"),
                "detectionState": rs.get("detectionState"),
                "remediationState": rs.get("remediationState"),
                "preRemediationDetectionScriptOutput": rs.get("preRemediationDetectionScriptOutput"),
                "postRemediationDetectionScriptOutput": rs.get("postRemediationDetectionScriptOutput"),
                "lastStateUpdateDateTime": rs.get("lastStateUpdateDateTime"),
            }
            for rs in run_states[:10]
        ]
    }


async def create_device_health_script(
    display_name: str,
    detection_script: str,
    remediation_script: str = "",
    description: str = "",
    publisher: str = "",
    run_as_account: str = "system",
    enforce_signature_check: bool = False,
    run_as_32_bit: bool = False
) -> dict[str, Any]:
    """
    Create a new proactive remediation script.
    
    Args:
        display_name: Script name
        detection_script: PowerShell detection script content
        remediation_script: PowerShell remediation script content
        description: Script description
        publisher: Publisher name
        run_as_account: "system" or "user"
        enforce_signature_check: Require script signing
        run_as_32_bit: Run in 32-bit PowerShell
    
    Returns:
        Created script details
    """
    client = get_graph_client()
    
    import base64
    detection_encoded = base64.b64encode(detection_script.encode('utf-8')).decode('utf-8')
    remediation_encoded = base64.b64encode(remediation_script.encode('utf-8')).decode('utf-8') if remediation_script else ""
    
    script_data = {
        "displayName": display_name,
        "description": description,
        "publisher": publisher,
        "detectionScriptContent": detection_encoded,
        "remediationScriptContent": remediation_encoded,
        "runAsAccount": run_as_account,
        "enforceSignatureCheck": enforce_signature_check,
        "runAs32Bit": run_as_32_bit,
    }
    
    result = await client.post(
        "/deviceManagement/deviceHealthScripts",
        json=script_data,
        use_beta=True
    )
    
    return {
        "status": "success",
        "message": f"Proactive remediation '{display_name}' created",
        "script": {
            "id": result.get("id"),
            "displayName": result.get("displayName"),
        }
    }


async def assign_device_health_script(
    script_id: str,
    group_ids: list,
    run_schedule: dict = None
) -> dict[str, Any]:
    """
    Assign a proactive remediation script to groups.
    
    Args:
        script_id: The script ID
        group_ids: List of group IDs to assign
        run_schedule: Schedule configuration (e.g., {"interval": 1, "useUtc": True})
    
    Returns:
        Status of the assignment
    """
    client = get_graph_client()
    
    script = await client.get(
        f"/deviceManagement/deviceHealthScripts/{script_id}?$select=displayName",
        use_beta=True
    )
    
    assignments = [
        {
            "target": {
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": gid
            },
            "runSchedule": run_schedule or {
                "@odata.type": "#microsoft.graph.deviceHealthScriptDailySchedule",
                "interval": 1,
                "useUtc": True,
                "time": "00:00:00"
            },
            "runRemediationScript": True
        }
        for gid in group_ids
    ]
    
    await client.post(
        f"/deviceManagement/deviceHealthScripts/{script_id}/assign",
        json={"deviceHealthScriptAssignments": assignments},
        use_beta=True
    )
    
    return {
        "status": "success",
        "message": f"Proactive remediation '{script.get('displayName')}' assigned to {len(group_ids)} group(s)"
    }


async def delete_device_health_script(script_id: str, confirm: bool = False) -> dict[str, Any]:
    """
    Delete a proactive remediation script.
    
    Args:
        script_id: The script ID
        confirm: Must be True to execute
    
    Returns:
        Deletion status
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "⚠️ DELETE will remove the proactive remediation! Set confirm=True to proceed."
        }
    
    client = get_graph_client()
    
    script = await client.get(
        f"/deviceManagement/deviceHealthScripts/{script_id}?$select=displayName",
        use_beta=True
    )
    
    await client.delete(
        f"/deviceManagement/deviceHealthScripts/{script_id}",
        use_beta=True
    )
    
    return {
        "status": "success",
        "message": f"Proactive remediation '{script.get('displayName')}' deleted"
    }


# ============== SHELL SCRIPTS (macOS/Linux) ==============

async def list_device_shell_scripts() -> dict[str, Any]:
    """
    List all shell scripts (for macOS/Linux) deployed through Intune.
    
    Returns:
        List of shell scripts
    """
    client = get_graph_client()
    
    response = await client.get(
        "/deviceManagement/deviceShellScripts",
        use_beta=True
    )
    scripts = response.get("value", [])
    
    return {
        "count": len(scripts),
        "scripts": [
            {
                "id": s.get("id"),
                "displayName": s.get("displayName"),
                "description": s.get("description"),
                "runAsAccount": s.get("runAsAccount"),
                "fileName": s.get("fileName"),
                "retryCount": s.get("retryCount"),
                "blockExecutionNotifications": s.get("blockExecutionNotifications"),
                "createdDateTime": s.get("createdDateTime"),
                "lastModifiedDateTime": s.get("lastModifiedDateTime"),
            }
            for s in scripts
        ]
    }


async def get_device_shell_script(script_id: str) -> dict[str, Any]:
    """
    Get details of a specific shell script.
    
    Args:
        script_id: The script ID
    
    Returns:
        Shell script details
    """
    client = get_graph_client()
    
    script = await client.get(
        f"/deviceManagement/deviceShellScripts/{script_id}",
        use_beta=True
    )
    
    # Decode script content
    script_content = script.get("scriptContent")
    if script_content:
        import base64
        try:
            decoded_content = base64.b64decode(script_content).decode('utf-8')
        except:
            decoded_content = "[Unable to decode script content]"
    else:
        decoded_content = None
    
    return {
        "id": script.get("id"),
        "displayName": script.get("displayName"),
        "description": script.get("description"),
        "runAsAccount": script.get("runAsAccount"),
        "fileName": script.get("fileName"),
        "scriptContent": decoded_content,
        "retryCount": script.get("retryCount"),
        "blockExecutionNotifications": script.get("blockExecutionNotifications"),
        "createdDateTime": script.get("createdDateTime"),
        "lastModifiedDateTime": script.get("lastModifiedDateTime"),
    }


async def create_device_shell_script(
    display_name: str,
    script_content: str,
    description: str = "",
    run_as_account: str = "system",
    file_name: str = "script.sh",
    retry_count: int = 3,
    block_execution_notifications: bool = False
) -> dict[str, Any]:
    """
    Create a new shell script for macOS/Linux deployment.
    
    Args:
        display_name: Script name
        script_content: The shell script content
        description: Script description
        run_as_account: "system" or "user"
        file_name: Script file name
        retry_count: Number of retries on failure
        block_execution_notifications: Hide execution notifications
    
    Returns:
        Created script details
    """
    client = get_graph_client()
    
    import base64
    encoded_content = base64.b64encode(script_content.encode('utf-8')).decode('utf-8')
    
    script_data = {
        "displayName": display_name,
        "description": description,
        "scriptContent": encoded_content,
        "runAsAccount": run_as_account,
        "fileName": file_name,
        "retryCount": retry_count,
        "blockExecutionNotifications": block_execution_notifications,
    }
    
    result = await client.post(
        "/deviceManagement/deviceShellScripts",
        json=script_data,
        use_beta=True
    )
    
    return {
        "status": "success",
        "message": f"Shell script '{display_name}' created",
        "script": {
            "id": result.get("id"),
            "displayName": result.get("displayName"),
        }
    }

