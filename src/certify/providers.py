from __future__ import annotations

import json
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from urllib.parse import urlparse


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
