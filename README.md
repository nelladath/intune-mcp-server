# 🖥️ Intune MCP Server

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)
[![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-API-blue.svg)](https://docs.microsoft.com/graph/)

A **Model Context Protocol (MCP) server** that enables AI assistants (like Claude in Cursor) to manage Microsoft Intune through the Microsoft Graph API.

> Created by [Sujin Nelladath](https://github.com/nelladath) - Microsoft Graph MVP

## ✨ Features

| Category | Capabilities |
|----------|-------------|
| 🖥️ **Device Management** | List, search, sync, restart, lock, wipe, retire devices |
| 📱 **App Management** | List apps, view assignments, search applications |
| 📋 **Policy Management** | Compliance policies, configuration profiles |
| 🚀 **Autopilot** | List devices, deployment profiles |
| 👥 **Users & Groups** | Search users, list groups, view memberships |

## 🚀 Quick Start

### Prerequisites

1. **Python 3.10+**
2. **Azure AD App Registration** with Microsoft Graph permissions

### Installation

```bash
# Clone the repository
git clone https://github.com/nelladath/intune-mcp-server.git
cd intune-mcp-server

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\Activate.ps1

# Install dependencies
pip install -e .
```

### Azure AD Setup

1. Go to **Azure Portal** → **Azure Active Directory** → **App registrations**
2. Click **New registration**
3. Name: `Intune MCP Server`
4. Add these **Application permissions** under Microsoft Graph:
   - `DeviceManagementManagedDevices.ReadWrite.All`
   - `DeviceManagementApps.ReadWrite.All`
   - `DeviceManagementConfiguration.ReadWrite.All`
   - `Directory.Read.All`
   - `Group.ReadWrite.All`
   - `User.Read.All`
5. **Grant admin consent**
6. Create a **Client Secret**

### Configuration

Create a `.env` file:

```env
TENANT_ID=your-tenant-id
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret
```

## 🔧 Cursor IDE Setup

Add to your Cursor MCP settings (`%APPDATA%\Cursor\User\globalStorage\cursor.mcp\mcp.json`):

```json
{
  "mcpServers": {
    "intune": {
      "command": "python",
      "args": ["-m", "intune_mcp_server.server"],
      "cwd": "C:\\path\\to\\intune-mcp-server",
      "env": {
        "TENANT_ID": "your-tenant-id",
        "CLIENT_ID": "your-client-id",
        "CLIENT_SECRET": "your-client-secret"
      }
    }
  }
}
```

**Restart Cursor** after adding the configuration.

## 📚 Available Tools

### Device Management
| Tool | Description |
|------|-------------|
| `list_managed_devices` | List all Intune managed devices |
| `get_device_details` | Get comprehensive device information |
| `search_devices` | Search by name, user, or serial number |
| `sync_device` | Trigger device sync |
| `restart_device` | Restart device remotely |
| `remote_lock_device` | Lock device remotely |
| `wipe_device` | Factory reset (requires confirmation) |
| `retire_device` | Remove company data (requires confirmation) |
| `get_noncompliant_devices` | List non-compliant devices |

### App Management
| Tool | Description |
|------|-------------|
| `list_mobile_apps` | List all Intune apps |
| `get_app_details` | Get app info and assignments |
| `search_apps` | Search apps by name |

### Policy Management
| Tool | Description |
|------|-------------|
| `list_compliance_policies` | List compliance policies |
| `list_configuration_profiles` | List configuration profiles |

### Autopilot
| Tool | Description |
|------|-------------|
| `list_autopilot_devices` | List Autopilot devices |
| `list_autopilot_profiles` | List deployment profiles |

### Users & Groups
| Tool | Description |
|------|-------------|
| `get_user` | Get user details |
| `search_users` | Search for users |
| `get_user_devices` | Get user's devices |
| `list_groups` | List Azure AD groups |
| `search_groups` | Search for groups |

## 💬 Example Usage

Once configured, ask your AI assistant:

- *"List all non-compliant devices"*
- *"Show me details for device XYZ"*
- *"Sync all devices for user john@company.com"*
- *"What apps are assigned to the Sales group?"*
- *"List Windows Autopilot devices"*

## ⚠️ Security Notes

- **Never commit `.env` files** to version control
- Destructive actions (wipe, retire) require explicit `confirm=True`
- Use **least privilege** - only grant necessary permissions
- Test in a **non-production tenant** first

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Sujin Nelladath** - Microsoft Graph MVP

- GitHub: [@nelladath](https://github.com/nelladath)
- LinkedIn: [sujin-nelladath](https://www.linkedin.com/in/sujin-nelladath-8911968a)

## 🙏 Acknowledgments

- [Model Context Protocol](https://modelcontextprotocol.io/) by Anthropic
- [Microsoft Graph API](https://docs.microsoft.com/graph/)
- [Cursor IDE](https://cursor.sh/)
