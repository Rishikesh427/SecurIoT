"""Authenticated, bounded HTTP calls. No redirects or credential logging."""
import http.client
import ipaddress
import json
from urllib.parse import urlencode, urlsplit


class CloudError(Exception):
    pass


class CloudClient:
    def __init__(self, base_url, api_key, timeout=3):
        url = urlsplit(base_url)
        if url.username or url.password or url.query or url.fragment or not url.hostname:
            raise ValueError("API URL must have a host and no credentials, query, or fragment")
        local = url.hostname == "localhost"
        try:
            local = local or ipaddress.ip_address(url.hostname).is_loopback
        except ValueError:
            pass
        if url.scheme != "https" and not (url.scheme == "http" and local):
            raise ValueError("Use HTTPS, or HTTP on loopback for local testing")
        if not api_key or any(c in api_key for c in "\r\n"):
            raise ValueError("AGENT_API_KEY is required and must be one line")
        self.url, self.api_key, self.timeout = url, api_key, timeout
        self.identity = base_url.rstrip("/")

    def request(self, method, path, payload=None, query=None):
        connection_type = http.client.HTTPSConnection if self.url.scheme == "https" else http.client.HTTPConnection
        connection = connection_type(self.url.hostname, self.url.port, timeout=self.timeout)
        target = self.url.path.rstrip("/") + path
        if query:
            target += "?" + urlencode(query)
        body = None if payload is None else json.dumps(payload, allow_nan=False).encode()
        try:
            connection.request(method, target, body=body, headers={
                "X-API-Key": self.api_key, "Content-Type": "application/json", "Accept": "application/json"})
            response = connection.getresponse()
            data = response.read(4 * 1024 * 1024 + 1)
            if len(data) > 4 * 1024 * 1024:
                raise CloudError("API response exceeded size limit")
            if response.status not in (200, 204, 304):
                raise CloudError(f"API returned HTTP {response.status}")
            if response.status in (204, 304):
                return response.status, None
            return response.status, json.loads(data)
        except (OSError, http.client.HTTPException, ValueError) as error:
            raise CloudError(f"API request failed ({type(error).__name__})") from None
        finally:
            connection.close()
