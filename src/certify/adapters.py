from __future__ import annotations

import json
import subprocess
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class CertificateBundle:
    certificate_pem: str
    private_key_pem: str | None
    chain_pem: str = ""


class TargetAdapter(ABC):
    @abstractmethod
    def deploy(self, bundle: CertificateBundle) -> None: ...


@dataclass(slots=True)
class SshAdapter(TargetAdapter):
    host: str
    user: str
    certificate_path: str
    key_path: str
    reload_command: tuple[str, ...] = ()
    port: int = 22

    def deploy(self, bundle: CertificateBundle) -> None:
        if bundle.private_key_pem is None:
            raise ValueError("target deployment requires an exportable private key")
        with tempfile.TemporaryDirectory(prefix="certify-") as directory:
            cert = Path(directory, "certificate.pem")
            key = Path(directory, "private-key.pem")
            cert.write_text(bundle.certificate_pem + bundle.chain_pem)
            key.write_text(bundle.private_key_pem)
            key.chmod(0o600)
            destination = f"{self.user}@{self.host}"
            common = ["-P", str(self.port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"]
            subprocess.run(["scp", *common, str(cert), f"{destination}:{self.certificate_path}"], check=True)
            subprocess.run(["scp", *common, str(key), f"{destination}:{self.key_path}"], check=True)
            if self.reload_command:
                subprocess.run(
                    ["ssh", "-p", str(self.port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", destination, "--", *self.reload_command],
                    check=True,
                )


class IisSshAdapter(SshAdapter):
    """IIS transport using the supported Windows OpenSSH service.

    The remote command should point to a constrained, signed PowerShell script
    which imports the PFX and updates the intended IIS binding.
    """


@dataclass(slots=True)
class FortiGateAdapter(TargetAdapter):
    """FortiOS 7.4 REST API adapter contract.

    Network execution is kept behind this boundary so deployments can supply a
    reviewed implementation matching their FortiGate authentication policy.
    """

    host: str
    api_token_reference: str
    vdom: str = "root"

    def deploy(self, bundle: CertificateBundle) -> None:
        raise NotImplementedError(
            "FortiGate deployment requires a site-specific credential backend; "
            "configure an approved FortiOS 7.4 implementation"
        )


def adapter_from_config(kind: str, config: dict[str, Any]) -> TargetAdapter:
    if kind == "linux-ssh":
        return SshAdapter(**config)
    if kind == "iis-ssh":
        return IisSshAdapter(**config)
    if kind == "fortigate-7.4":
        return FortiGateAdapter(**config)
    raise ValueError(f"unsupported target adapter: {kind}")


def parse_config(value: str) -> dict[str, Any]:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError("target configuration must be a JSON object")
    return parsed
