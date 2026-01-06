"""Policy and Compliance Management Tools for Intune MCP Server."""

from typing import Any
from mcp.server import Server

from ..graph_client import get_graph_client


def register_policy_tools(server: Server):
    """Register all policy management tools with the MCP server."""
    
    @server.tool()
    async def list_compliance_policies() -> dict[str, Any]:
        """
        List all device compliance policies.
        
        Returns:
            List of compliance policies
        """
        client = get_graph_client()
        
        response = await client.get("/deviceManagement/deviceCompliancePolicies")
        policies = response.get("value", [])
        
        return {
            "count": len(policies),
            "policies": [
                {
                    "id": p.get("id"),
                    "displayName": p.get("displayName"),
                    "description": p.get("description"),
                    "policyType": p.get("@odata.type", "").replace("#microsoft.graph.", ""),
                    "createdDateTime": p.get("createdDateTime"),
                    "lastModifiedDateTime": p.get("lastModifiedDateTime"),
                    "version": p.get("version"),
                }
                for p in policies
            ]
        }
    
    @server.tool()
    async def get_compliance_policy_details(policy_id: str) -> dict[str, Any]:
        """
        Get detailed information about a compliance policy.
        
        Args:
            policy_id: The compliance policy ID
        
        Returns:
            Policy details including settings and assignments
        """
        client = get_graph_client()
        
        # Get policy details
        policy = await client.get(f"/deviceManagement/deviceCompliancePolicies/{policy_id}")
        
        # Get assignments
        try:
            assignments = await client.get(
                f"/deviceManagement/deviceCompliancePolicies/{policy_id}/assignments"
            )
            assignment_list = assignments.get("value", [])
        except Exception:
            assignment_list = []
        
        # Get device status overview
        try:
            status = await client.get(
                f"/deviceManagement/deviceCompliancePolicies/{policy_id}/deviceStatusOverview"
            )
        except Exception:
            status = {}
        
        return {
            "policy": {
                "id": policy.get("id"),
                "displayName": policy.get("displayName"),
                "description": policy.get("description"),
                "policyType": policy.get("@odata.type", "").replace("#microsoft.graph.", ""),
                "createdDateTime": policy.get("createdDateTime"),
                "lastModifiedDateTime": policy.get("lastModifiedDateTime"),
            },
            "device_status_overview": {
                "pendingCount": status.get("pendingCount"),
                "notApplicableCount": status.get("notApplicableCount"),
                "successCount": status.get("successCount"),
                "errorCount": status.get("errorCount"),
                "failedCount": status.get("failedCount"),
                "lastUpdateDateTime": status.get("lastUpdateDateTime"),
            },
            "assignments": [
                {
                    "id": a.get("id"),
                    "targetType": a.get("target", {}).get("@odata.type", "").replace("#microsoft.graph.", ""),
                    "groupId": a.get("target", {}).get("groupId"),
                }
                for a in assignment_list
            ]
        }
    
    @server.tool()
    async def list_configuration_profiles() -> dict[str, Any]:
        """
        List all device configuration profiles.
        
        Returns:
            List of configuration profiles
        """
        client = get_graph_client()
        
        response = await client.get("/deviceManagement/deviceConfigurations")
        configs = response.get("value", [])
        
        return {
            "count": len(configs),
            "profiles": [
                {
                    "id": c.get("id"),
                    "displayName": c.get("displayName"),
                    "description": c.get("description"),
                    "profileType": c.get("@odata.type", "").replace("#microsoft.graph.", ""),
                    "createdDateTime": c.get("createdDateTime"),
                    "lastModifiedDateTime": c.get("lastModifiedDateTime"),
                    "version": c.get("version"),
                }
                for c in configs
            ]
        }
    
    @server.tool()
    async def get_configuration_profile_details(profile_id: str) -> dict[str, Any]:
        """
        Get detailed information about a configuration profile.
        
        Args:
            profile_id: The configuration profile ID
        
        Returns:
            Profile details including assignments and status
        """
        client = get_graph_client()
        
        profile = await client.get(f"/deviceManagement/deviceConfigurations/{profile_id}")
        
        # Get assignments
        try:
            assignments = await client.get(
                f"/deviceManagement/deviceConfigurations/{profile_id}/assignments"
            )
            assignment_list = assignments.get("value", [])
        except Exception:
            assignment_list = []
        
        # Get status overview
        try:
            status = await client.get(
                f"/deviceManagement/deviceConfigurations/{profile_id}/deviceStatusOverview"
            )
        except Exception:
            status = {}
        
        return {
            "profile": {
                "id": profile.get("id"),
                "displayName": profile.get("displayName"),
                "description": profile.get("description"),
                "profileType": profile.get("@odata.type", "").replace("#microsoft.graph.", ""),
                "createdDateTime": profile.get("createdDateTime"),
                "lastModifiedDateTime": profile.get("lastModifiedDateTime"),
            },
            "device_status_overview": {
                "pendingCount": status.get("pendingCount"),
                "notApplicableCount": status.get("notApplicableCount"),
                "successCount": status.get("successCount"),
                "errorCount": status.get("errorCount"),
                "failedCount": status.get("failedCount"),
            },
            "assignments": [
                {
                    "id": a.get("id"),
                    "targetType": a.get("target", {}).get("@odata.type", "").replace("#microsoft.graph.", ""),
                    "groupId": a.get("target", {}).get("groupId"),
                }
                for a in assignment_list
            ]
        }
    
    @server.tool()
    async def assign_compliance_policy(
        policy_id: str,
        group_id: str
    ) -> dict[str, Any]:
        """
        Assign a compliance policy to a group.
        
        Args:
            policy_id: The compliance policy ID
            group_id: The Azure AD group ID
        
        Returns:
            Status of the assignment
        """
        client = get_graph_client()
        
        policy = await client.get(
            f"/deviceManagement/deviceCompliancePolicies/{policy_id}?$select=displayName"
        )
        group = await client.get(f"/groups/{group_id}?$select=displayName")
        
        assignment_body = {
            "assignments": [
                {
                    "target": {
                        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                        "groupId": group_id
                    }
                }
            ]
        }
        
        await client.post(
            f"/deviceManagement/deviceCompliancePolicies/{policy_id}/assign",
            json=assignment_body
        )
        
        return {
            "status": "success",
            "message": f"Policy '{policy.get('displayName')}' assigned to group '{group.get('displayName')}'",
            "policy_id": policy_id,
            "group_id": group_id
        }
    
    @server.tool()
    async def assign_configuration_profile(
        profile_id: str,
        group_id: str
    ) -> dict[str, Any]:
        """
        Assign a configuration profile to a group.
        
        Args:
            profile_id: The configuration profile ID
            group_id: The Azure AD group ID
        
        Returns:
            Status of the assignment
        """
        client = get_graph_client()
        
        profile = await client.get(
            f"/deviceManagement/deviceConfigurations/{profile_id}?$select=displayName"
        )
        group = await client.get(f"/groups/{group_id}?$select=displayName")
        
        assignment_body = {
            "assignments": [
                {
                    "target": {
                        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                        "groupId": group_id
                    }
                }
            ]
        }
        
        await client.post(
            f"/deviceManagement/deviceConfigurations/{profile_id}/assign",
            json=assignment_body
        )
        
        return {
            "status": "success",
            "message": f"Profile '{profile.get('displayName')}' assigned to group '{group.get('displayName')}'",
            "profile_id": profile_id,
            "group_id": group_id
        }
    
    @server.tool()
    async def list_conditional_access_policies() -> dict[str, Any]:
        """
        List all Conditional Access policies.
        
        Returns:
            List of Conditional Access policies
        """
        client = get_graph_client()
        
        response = await client.get("/identity/conditionalAccess/policies")
        policies = response.get("value", [])
        
        return {
            "count": len(policies),
            "policies": [
                {
                    "id": p.get("id"),
                    "displayName": p.get("displayName"),
                    "state": p.get("state"),
                    "createdDateTime": p.get("createdDateTime"),
                    "modifiedDateTime": p.get("modifiedDateTime"),
                }
                for p in policies
            ]
        }
    
    @server.tool()
    async def get_conditional_access_policy(policy_id: str) -> dict[str, Any]:
        """
        Get details of a Conditional Access policy.
        
        Args:
            policy_id: The policy ID
        
        Returns:
            Policy details including conditions and grant controls
        """
        client = get_graph_client()
        
        policy = await client.get(f"/identity/conditionalAccess/policies/{policy_id}")
        
        return {
            "id": policy.get("id"),
            "displayName": policy.get("displayName"),
            "state": policy.get("state"),
            "conditions": {
                "users": policy.get("conditions", {}).get("users", {}),
                "applications": policy.get("conditions", {}).get("applications", {}),
                "platforms": policy.get("conditions", {}).get("platforms", {}),
                "locations": policy.get("conditions", {}).get("locations", {}),
                "clientAppTypes": policy.get("conditions", {}).get("clientAppTypes", []),
            },
            "grantControls": policy.get("grantControls", {}),
            "sessionControls": policy.get("sessionControls", {}),
        }
    
    @server.tool()
    async def get_policy_compliance_report() -> dict[str, Any]:
        """
        Get an overall compliance report across all policies.
        
        Returns:
            Summary of compliance status across all policies
        """
        client = get_graph_client()
        
        # Get all compliance policies
        policies = await client.get("/deviceManagement/deviceCompliancePolicies")
        policy_list = policies.get("value", [])
        
        report = []
        for policy in policy_list:
            try:
                status = await client.get(
                    f"/deviceManagement/deviceCompliancePolicies/{policy['id']}/deviceStatusOverview"
                )
                report.append({
                    "policy_name": policy.get("displayName"),
                    "policy_id": policy.get("id"),
                    "success": status.get("successCount", 0),
                    "pending": status.get("pendingCount", 0),
                    "failed": status.get("failedCount", 0),
                    "error": status.get("errorCount", 0),
                    "not_applicable": status.get("notApplicableCount", 0),
                })
            except Exception:
                report.append({
                    "policy_name": policy.get("displayName"),
                    "policy_id": policy.get("id"),
                    "status": "Unable to retrieve"
                })
        
        return {
            "total_policies": len(report),
            "policy_reports": report
        }
    
    @server.tool()
    async def list_windows_update_rings() -> dict[str, Any]:
        """
        List Windows Update for Business rings.
        
        Returns:
            List of Windows Update rings
        """
        client = get_graph_client()
        
        response = await client.get("/deviceManagement/deviceConfigurations?$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')")
        rings = response.get("value", [])
        
        return {
            "count": len(rings),
            "update_rings": [
                {
                    "id": r.get("id"),
                    "displayName": r.get("displayName"),
                    "description": r.get("description"),
                    "qualityUpdatesDeferralPeriodInDays": r.get("qualityUpdatesDeferralPeriodInDays"),
                    "featureUpdatesDeferralPeriodInDays": r.get("featureUpdatesDeferralPeriodInDays"),
                    "automaticUpdateMode": r.get("automaticUpdateMode"),
                }
                for r in rings
            ]
        }
    
    @server.tool()
    async def list_security_baselines() -> dict[str, Any]:
        """
        List security baseline profiles (using beta endpoint).
        
        Returns:
            List of security baselines
        """
        client = get_graph_client()
        
        # Security baselines are in beta
        response = await client.get(
            "/deviceManagement/templates?$filter=templateType eq 'securityBaseline'",
            use_beta=True
        )
        baselines = response.get("value", [])
        
        return {
            "count": len(baselines),
            "baselines": [
                {
                    "id": b.get("id"),
                    "displayName": b.get("displayName"),
                    "description": b.get("description"),
                    "versionInfo": b.get("versionInfo"),
                    "publishedDateTime": b.get("publishedDateTime"),
                }
                for b in baselines
            ]
        }

