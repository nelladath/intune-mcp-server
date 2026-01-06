"""Microsoft Graph API Client with authentication."""

import asyncio
from datetime import datetime, timedelta
from typing import Any

import httpx
from msal import ConfidentialClientApplication

from .config import get_config, GraphConfig


class GraphClient:
    """Async Microsoft Graph API client with automatic token management."""
    
    def __init__(self, config: GraphConfig | None = None):
        """Initialize the Graph client."""
        self.config = config or get_config()
        self._token: str | None = None
        self._token_expires: datetime | None = None
        self._msal_app: ConfidentialClientApplication | None = None
        self._http_client: httpx.AsyncClient | None = None
    
    @property
    def msal_app(self) -> ConfidentialClientApplication:
        """Get or create the MSAL application."""
        if self._msal_app is None:
            self._msal_app = ConfidentialClientApplication(
                client_id=self.config.client_id,
                client_credential=self.config.client_secret,
                authority=f"https://login.microsoftonline.com/{self.config.tenant_id}",
            )
        return self._msal_app
    
    async def get_token(self) -> str:
        """Get a valid access token, refreshing if necessary."""
        # Check if we have a valid cached token
        if self._token and self._token_expires and datetime.now() < self._token_expires:
            return self._token
        
        # Acquire new token
        scopes = ["https://graph.microsoft.com/.default"]
        
        # Run MSAL token acquisition in thread pool (it's synchronous)
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: self.msal_app.acquire_token_for_client(scopes=scopes)
        )
        
        if "access_token" in result:
            self._token = result["access_token"]
            # Token typically expires in 1 hour, refresh 5 minutes early
            expires_in = result.get("expires_in", 3600)
            self._token_expires = datetime.now() + timedelta(seconds=expires_in - 300)
            return self._token
        else:
            error = result.get("error_description", result.get("error", "Unknown error"))
            raise Exception(f"Failed to acquire token: {error}")
    
    async def get_http_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client
    
    async def _request(
        self,
        method: str,
        endpoint: str,
        use_beta: bool = False,
        **kwargs
    ) -> dict[str, Any]:
        """Make an authenticated request to Microsoft Graph."""
        token = await self.get_token()
        client = await self.get_http_client()
        
        base_url = self.config.beta_endpoint if use_beta else self.config.graph_endpoint
        url = f"{base_url}{endpoint}" if endpoint.startswith("/") else f"{base_url}/{endpoint}"
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            **kwargs.pop("headers", {})
        }
        
        response = await client.request(method, url, headers=headers, **kwargs)
        
        # Handle different response codes
        if response.status_code == 204:  # No content
            return {"status": "success", "message": "Operation completed successfully"}
        
        if response.status_code >= 400:
            try:
                error_data = response.json()
                error_message = error_data.get("error", {}).get("message", response.text)
            except Exception:
                error_message = response.text
            raise Exception(f"Graph API error ({response.status_code}): {error_message}")
        
        return response.json()
    
    async def get(self, endpoint: str, use_beta: bool = False, **kwargs) -> dict[str, Any]:
        """Make a GET request."""
        return await self._request("GET", endpoint, use_beta=use_beta, **kwargs)
    
    async def post(self, endpoint: str, use_beta: bool = False, **kwargs) -> dict[str, Any]:
        """Make a POST request."""
        return await self._request("POST", endpoint, use_beta=use_beta, **kwargs)
    
    async def patch(self, endpoint: str, use_beta: bool = False, **kwargs) -> dict[str, Any]:
        """Make a PATCH request."""
        return await self._request("PATCH", endpoint, use_beta=use_beta, **kwargs)
    
    async def delete(self, endpoint: str, use_beta: bool = False, **kwargs) -> dict[str, Any]:
        """Make a DELETE request."""
        return await self._request("DELETE", endpoint, use_beta=use_beta, **kwargs)
    
    async def get_all_pages(
        self,
        endpoint: str,
        use_beta: bool = False,
        max_pages: int = 100
    ) -> list[dict[str, Any]]:
        """Get all pages of a paginated response."""
        all_items = []
        current_endpoint = endpoint
        page_count = 0
        
        while current_endpoint and page_count < max_pages:
            if page_count > 0:
                # For subsequent pages, the endpoint is a full URL
                response = await self._request("GET", "", use_beta=use_beta)
                # Actually we need to handle nextLink differently
                token = await self.get_token()
                client = await self.get_http_client()
                headers = {"Authorization": f"Bearer {token}"}
                resp = await client.get(current_endpoint, headers=headers)
                response = resp.json()
            else:
                response = await self.get(current_endpoint, use_beta=use_beta)
            
            items = response.get("value", [])
            all_items.extend(items)
            
            # Check for next page
            current_endpoint = response.get("@odata.nextLink")
            page_count += 1
        
        return all_items
    
    async def close(self):
        """Close the HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None


# Global client instance (lazy loaded)
_client: GraphClient | None = None


def get_graph_client() -> GraphClient:
    """Get the global Graph client instance."""
    global _client
    if _client is None:
        _client = GraphClient()
    return _client

