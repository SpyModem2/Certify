from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "packaging" / "configure-tls.sh"


def run_tls(tmp_path: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ | {
        "CERTIFY_TLS_ALLOW_UNPRIVILEGED": "true",
        "CERTIFY_TLS_DIR": str(tmp_path / "installed"),
        "CERTIFY_TLS_OWNER": f"{os.getuid()}:{os.getgid()}",
        "SYSTEMCTL_BIN": "false",
    }
    return subprocess.run(
        ["bash", str(SCRIPT), *arguments],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def create_certificate(tmp_path: Path, name: str) -> tuple[Path, Path]:
    certificate = tmp_path / f"{name}.pem"
    key = tmp_path / f"{name}.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "1", "-subj", f"/CN={name}", "-keyout", str(key),
            "-out", str(certificate),
        ],
        check=True,
        capture_output=True,
    )
    return certificate, key


def test_self_signed_certificate_has_san_and_safe_key_permissions(tmp_path: Path) -> None:
    result = run_tls(tmp_path, "self-signed", "certify.example.test", "1")

    assert result.returncode == 0, result.stderr
    cert = tmp_path / "installed" / "fullchain.pem"
    key = tmp_path / "installed" / "privkey.pem"
    details = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-noout", "-ext", "subjectAltName"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "DNS:certify.example.test" in details
    assert stat.S_IMODE(key.stat().st_mode) == 0o640


def test_custom_certificate_and_chain_are_installed(tmp_path: Path) -> None:
    certificate, key = create_certificate(tmp_path, "server")
    chain, _ = create_certificate(tmp_path, "issuer")

    result = run_tls(tmp_path, "custom", str(certificate), str(key), str(chain))

    assert result.returncode == 0, result.stderr
    fullchain = (tmp_path / "installed" / "fullchain.pem").read_text()
    assert fullchain.count("-----BEGIN CERTIFICATE-----") == 2


def test_custom_certificate_rejects_mismatched_key(tmp_path: Path) -> None:
    certificate, _ = create_certificate(tmp_path, "server")
    _, wrong_key = create_certificate(tmp_path, "other")

    result = run_tls(tmp_path, "custom", str(certificate), str(wrong_key))

    assert result.returncode != 0
    assert "passen nicht zusammen" in result.stderr
