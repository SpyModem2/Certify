from __future__ import annotations

import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).parents[1]
INSTALL_COMMON = ROOT / "packaging" / "install-common.sh"


def _command(path: Path, name: str, body: str) -> None:
    executable = path / name
    executable.write_text(f"#!/usr/bin/env bash\n{body}\n")
    executable.chmod(0o755)


def _run_function(
    tmp_path: Path, function: str, extra_environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PATH"] = f"{tmp_path}:{environment['PATH']}"
    environment["CALL_LOG"] = str(tmp_path / "calls")
    environment.update(extra_environment or {})
    return subprocess.run(
        ["bash", "-c", f"source {INSTALL_COMMON!s}; {function}"],
        text=True,
        capture_output=True,
        env=environment,
        check=False,
    )


def test_firewalld_opens_https_for_normal_tls(tmp_path: Path) -> None:
    _command(tmp_path, "firewall-cmd", 'echo "$*" >>"$CALL_LOG"')

    result = _run_function(tmp_path, "configure_firewall self-signed")

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "calls").read_text().splitlines() == [
        "--state",
        "--permanent --add-service=https",
        "--add-service=https",
    ]


def test_firewalld_also_opens_http_for_letsencrypt(tmp_path: Path) -> None:
    _command(tmp_path, "firewall-cmd", 'echo "$*" >>"$CALL_LOG"')

    result = _run_function(tmp_path, "configure_firewall letsencrypt")

    assert result.returncode == 0, result.stderr
    calls = (tmp_path / "calls").read_text().splitlines()
    assert "--permanent --add-service=http" in calls
    assert "--add-service=http" in calls


def test_selinux_restores_all_installed_paths(tmp_path: Path) -> None:
    _command(tmp_path, "getenforce", "echo Enforcing")
    _command(tmp_path, "restorecon", 'echo "$*" >>"$CALL_LOG"')

    result = _run_function(tmp_path, "configure_selinux")

    assert result.returncode == 0, result.stderr
    call = (tmp_path / "calls").read_text()
    assert "-RF /etc/certify /opt/certify /var/lib/certify" in call
    assert "/etc/systemd/system/certify.service" in call
    assert "/usr/local/sbin/certify-configure-tls" in call


def test_disabled_selinux_does_not_call_restorecon(tmp_path: Path) -> None:
    _command(tmp_path, "getenforce", "echo Disabled")
    _command(tmp_path, "restorecon", 'echo called >>"$CALL_LOG"')

    result = _run_function(tmp_path, "configure_selinux")

    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "calls").exists()


def test_missing_selinux_package_can_be_installed_automatically(tmp_path: Path) -> None:
    _command(tmp_path, "getenforce", "echo Enforcing")
    _command(
        tmp_path,
        "dnf",
        'echo "$*" >>"$CALL_LOG"; '
        'printf \'#!/usr/bin/env bash\\necho "$*" >>"$CALL_LOG"\\n\' >"$(dirname "$0")/restorecon"; '
        'chmod +x "$(dirname "$0")/restorecon"',
    )

    result = _run_function(
        tmp_path,
        "configure_selinux",
        {"CERTIFY_INSTALL_MISSING_PACKAGES": "true"},
    )

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "calls").read_text().splitlines()[0] == "install -y policycoreutils"


def test_missing_selinux_package_is_not_silently_ignored(tmp_path: Path) -> None:
    _command(tmp_path, "getenforce", "echo Enforcing")
    _command(tmp_path, "dnf", 'echo "$*" >>"$CALL_LOG"')

    result = _run_function(
        tmp_path,
        "configure_selinux",
        {"CERTIFY_NON_INTERACTIVE": "true"},
    )

    assert result.returncode == 1
    assert "CERTIFY_INSTALL_MISSING_PACKAGES=true" in result.stderr
    assert not (tmp_path / "calls").exists()
