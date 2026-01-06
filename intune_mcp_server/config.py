"""Configuration management for Microsoft Graph MCP Server."""

import os
from dataclasses import dataclass
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


@dataclass
class GraphConfig:
    """Microsoft Graph API configuration."""
    
    tenant_id: str
    client_id: str
    client_secret: str
    graph_endpoint: str = "https://graph.microsoft.com/v1.0"
    beta_endpoint: str = "https://graph.microsoft.com/beta"
    
    @classmethod
    def from_env(cls) -> "GraphConfig":
        """Load configuration from environment variables."""
        tenant_id = os.getenv("TENANT_ID")
        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")
        
        if not all([tenant_id, client_id, client_secret]):
            raise ValueError(
                "Missing required environment variables. "
                "Please set TENANT_ID, CLIENT_ID, and CLIENT_SECRET in your .env file."
            )
        
        return cls(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            graph_endpoint=os.getenv("GRAPH_ENDPOINT", "https://graph.microsoft.com/v1.0"),
            beta_endpoint=os.getenv("BETA_ENDPOINT", "https://graph.microsoft.com/beta"),
        )


# Global config instance (lazy loaded)
_config: GraphConfig | None = None


def get_config() -> GraphConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = GraphConfig.from_env()
    return _config

