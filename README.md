# Microsoft Intune & Entra ID MCP Server

A comprehensive Model Context Protocol (MCP) server for managing Microsoft Intune and Entra ID (Azure AD) through the Microsoft Graph API. This server enables AI assistants like Claude to perform device management, user administration, security configuration, and more.

## 🚀 Features

### **Intune Device Management**
- List, search, and manage devices
- Compliance monitoring and reporting
- Remote actions (sync, restart, lock, wipe, retire)
- Autopilot device management
- Device configuration profiles
- Compliance policies

### **Entra ID (Azure AD) User Management**
- Full user CRUD operations
- Password management and reset
- License assignment and management
- User enable/disable
- Session revocation
- Sign-in activity tracking
- Deleted user recovery

### **Group Management**
- Security groups (static and dynamic)
- Microsoft 365 groups
- Member and owner management
- Dynamic membership rules
- Bulk member operations

### **Conditional Access**
- Policy listing and management
- Enable/disable policies
- Named locations management
- Policy coverage analysis

### **Authentication & Identity Protection**
- MFA status monitoring
- Authentication methods management
- Sign-in logs
- Risky user detection
- Risk detections and alerts
- Directory audit logs

### **Windows 365 Cloud PC**
- List and manage Cloud PCs
- Provisioning policies
- Restart, reprovision actions
- Gallery and custom images
- User settings management

### **Tenant Administration**
- Organization information
- Domain management
- Service health monitoring
- Directory roles
- License/subscription management
- App registrations

### **Scripts & Remediations**
- PowerShell script management
- Proactive remediations
- Shell scripts (macOS/Linux)
- Script deployment status

### **Security & Compliance**
- Security baselines
- Endpoint security policies
- App protection policies (MAM)
- Enrollment restrictions
- Device categories
- BitLocker recovery keys

### **Reports**
- Device compliance reports
- Configuration profile status
- App installation status
- License usage reports
- Hardware inventory

## 📋 Prerequisites

- Python 3.11+
- Microsoft Entra ID (Azure AD) tenant
- App registration with appropriate permissions

## 🔐 Required API Permissions

Add these permissions to your app registration in Azure Portal:

### Intune
```
DeviceManagementManagedDevices.ReadWrite.All
DeviceManagementConfiguration.ReadWrite.All
DeviceManagementApps.ReadWrite.All
DeviceManagementServiceConfig.ReadWrite.All
```

### Entra ID
```
User.ReadWrite.All
Group.ReadWrite.All
Directory.ReadWrite.All
RoleManagement.ReadWrite.Directory
Policy.ReadWrite.ConditionalAccess
IdentityRiskyUser.ReadWrite.All
IdentityRiskEvent.Read.All
AuditLog.Read.All
UserAuthenticationMethod.ReadWrite.All
```

### Windows 365
```
CloudPC.ReadWrite.All
```

### Service Health & Reports
```
ServiceHealth.Read.All
Reports.Read.All
```

### Other
```
Organization.Read.All
Domain.Read.All
Application.Read.All
```

## 🛠️ Installation

1. **Clone or download the repository**

2. **Create a virtual environment**
```bash
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/macOS
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment variables**

Create a `.env` file or set environment variables:
```env
TENANT_ID=your-tenant-id
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret
```

## ⚙️ Configuration for Cursor

Add to your Cursor MCP configuration (`~/.cursor/mcp.json` on Windows: `%USERPROFILE%\.cursor\mcp.json`):

```json
{
  "mcpServers": {
    "intune": {
      "command": "C:\\MCP\\venv\\Scripts\\python.exe",
      "args": ["C:\\MCP\\intune_mcp_server\\server.py"],
      "env": {
        "TENANT_ID": "your-tenant-id",
        "CLIENT_ID": "your-client-id",
        "CLIENT_SECRET": "your-client-secret"
      }
    }
  }
}
```

## 📚 Available Tools

### Device Management
| Tool | Description |
|------|-------------|
| `list_managed_devices` | List all Intune managed devices |
| `get_device_details` | Get comprehensive device information |
| `search_devices` | Search devices by name, user, or serial |
| `get_noncompliant_devices` | List non-compliant devices |
| `sync_device` | Trigger device sync |
| `restart_device` | Remotely restart device |
| `remote_lock_device` | Remotely lock device |
| `wipe_device` | Wipe device (destructive) |
| `retire_device` | Retire device |

### User Management
| Tool | Description |
|------|-------------|
| `list_users` | List all users |
| `get_user` | Get user details |
| `create_user` | Create new user |
| `update_user` | Update user properties |
| `delete_user` | Delete user |
| `enable_user` / `disable_user` | Enable/disable account |
| `reset_user_password` | Reset password |
| `revoke_user_sessions` | Force re-authentication |
| `get_user_licenses` | Get license assignments |
| `assign_license` / `remove_license` | Manage licenses |

### Group Management
| Tool | Description |
|------|-------------|
| `list_groups` | List all groups |
| `get_group` | Get group details |
| `create_security_group` | Create security group |
| `create_microsoft365_group` | Create M365 group |
| `create_dynamic_security_group` | Create dynamic group |
| `get_group_members` | List group members |
| `add_group_member` / `remove_group_member` | Manage membership |

### Conditional Access
| Tool | Description |
|------|-------------|
| `list_conditional_access_policies` | List CA policies |
| `get_conditional_access_policy` | Get policy details |
| `enable_conditional_access_policy` | Enable policy |
| `disable_conditional_access_policy` | Disable policy |
| `list_named_locations` | List named locations |

### Authentication & Security
| Tool | Description |
|------|-------------|
| `get_user_authentication_methods` | List auth methods |
| `get_user_mfa_status` | Check MFA status |
| `get_sign_in_logs` | Get sign-in logs |
| `get_risky_users` | List risky users |
| `get_risk_detections` | Get risk detections |
| `get_directory_audit_logs` | Get audit logs |

### Cloud PC
| Tool | Description |
|------|-------------|
| `list_cloud_pcs` | List all Cloud PCs |
| `get_cloud_pc_details` | Get Cloud PC details |
| `restart_cloud_pc` | Restart Cloud PC |
| `reprovision_cloud_pc` | Reprovision Cloud PC |
| `list_provisioning_policies` | List provisioning policies |

### Reports
| Tool | Description |
|------|-------------|
| `get_device_compliance_report` | Compliance summary |
| `get_device_configuration_status` | Config profile status |
| `get_app_installation_status` | App install status |
| `get_license_usage_report` | License usage |

## 🔒 Security Considerations

1. **Client Secret Protection**: Never commit client secrets to version control
2. **Least Privilege**: Grant only required permissions
3. **Audit Logging**: Monitor API usage through Azure AD logs
4. **Destructive Actions**: All destructive operations require `confirm=True`

## 📝 Example Usage

Once configured, you can ask Claude to:

- "List all Windows devices in my tenant"
- "Show me non-compliant devices"
- "Create a new user john.doe@company.com"
- "Reset password for user X"
- "List all Conditional Access policies"
- "Show MFA status for user X"
- "Get Cloud PC overview"
- "Show me license usage"
- "List Global Administrators"

## 🆘 Troubleshooting

### Connection Issues
- Verify TENANT_ID, CLIENT_ID, and CLIENT_SECRET are correct
- Check app registration permissions in Azure Portal
- Ensure admin consent is granted for permissions

### Permission Errors
- Review required permissions above
- Grant admin consent in Azure Portal
- Some features require specific licenses (e.g., Entra ID P1/P2)

### Beta API Features
- Some features use Microsoft Graph beta endpoints
- Beta APIs may change without notice

## 📄 License

MIT License

## 🤝 Contributing

Contributions welcome! Please feel free to submit issues and pull requests.
