from __future__ import annotations

import json
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from urllib.parse import urlparse
from urllib.request import Request, urlopen


class DnsProvider(ABC):
    @abstractmethod
    def present(self, fqdn: str, value: str) -> None: ...

    @abstractmethod
    def cleanup(self, fqdn: str, value: str) -> None: ...


@dataclass(slots=True)
class WebhookDnsProvider(DnsProvider):
    """Run a locally installed, administrator-approved DNS hook.

    The hook receives JSON on stdin and must return successfully. It is never
    interpreted through a shell. This supports arbitrary DNS APIs without
    pulling provider SDKs and their dependency trees into the server.
    """

    executable: str
    timeout_seconds: int = 30

    def _invoke(self, operation: str, fqdn: str, value: str) -> None:
        subprocess.run(
            [self.executable],
            input=json.dumps({"operation": operation, "fqdn": fqdn, "value": value}),
            text=True,
            check=True,
            timeout=self.timeout_seconds,
            shell=False,
            capture_output=True,
        )

    def present(self, fqdn: str, value: str) -> None:
        self._invoke("present", fqdn, value)

    def cleanup(self, fqdn: str, value: str) -> None:
        self._invoke("cleanup", fqdn, value)


def validate_acme_directory(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username:
        raise ValueError("ACME directory must be an HTTPS URL without credentials")
    return url


def test_acme_connection(url: str, timeout_seconds: int = 10) -> dict[str, object]:
    """Fetch and validate the public ACME directory at *url*.

    ACME does not define a separate health-check operation.  Reading the
    directory is therefore the least invasive interoperable connection test:
    it verifies DNS, TLS, HTTP and the basic shape of the CA response without
    creating or changing an account at the provider.
    """

    validate_acme_directory(url)
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "Certify/0.1"})
    with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - administrator-configured HTTPS URL
        if response.status != 200:
            raise ValueError(f"ACME directory returned HTTP {response.status}")
        content_type = response.headers.get_content_type()
        if content_type not in ("application/json", "application/problem+json"):
            raise ValueError(f"ACME directory returned unsupported content type {content_type}")
        try:
            directory = json.load(response)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("ACME directory did not return valid JSON") from error

    required = ("newNonce", "newAccount", "newOrder")
    if not isinstance(directory, dict) or any(not isinstance(directory.get(key), str) for key in required):
        raise ValueError("ACME directory is missing required endpoints")
    return {"reachable": True, "endpoints": list(required)}
