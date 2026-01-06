"""Allow running as a module: python -m intune_mcp_server"""

from .server import mcp

if __name__ == "__main__":
    mcp.run()
