"""
Intune & Entra ID MCP Server Tools

This package contains all tool modules for the MCP server:
- entra_users: User management
- entra_groups: Group management
- entra_devices: Entra ID device management (delete, disable, enable)
- conditional_access: Conditional Access policies
- authentication: MFA, sign-in logs, identity protection
- reports: Compliance and deployment reports
- cloud_pc: Windows 365 Cloud PC management
- tenant_admin: Tenant administration
- scripts: PowerShell scripts and remediations
- security: Security baselines and endpoint protection
- app_registrations: App registrations and enterprise applications
"""

from . import entra_users
from . import entra_groups
from . import entra_devices
from . import conditional_access
from . import authentication
from . import reports
from . import cloud_pc
from . import tenant_admin
from . import scripts
from . import security
from . import app_registrations

__all__ = [
    'entra_users',
    'entra_groups',
    'entra_devices',
    'conditional_access',
    'authentication',
    'reports',
    'cloud_pc',
    'tenant_admin',
    'scripts',
    'security',
    'app_registrations',
]
