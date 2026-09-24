from __future__ import annotations

import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).parents[1]
INSTALL_COMMON = ROOT / "packaging" / "install-common.sh"
UPDATE_COMMON = ROOT / "packaging" / "update-common.sh"


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


def test_missing_selinux_package_is_installed_automatically(tmp_path: Path) -> None:
    _command(tmp_path, "getenforce", "echo Enforcing")
    _command(
        tmp_path,
        "dnf",
        'echo "$*" >>"$CALL_LOG"; '
        'printf \'#!/usr/bin/env bash\\necho "$*" >>"$CALL_LOG"\\n\' >"$(dirname "$0")/restorecon"; '
        'chmod +x "$(dirname "$0")/restorecon"',
    )

    result = _run_function(tmp_path, "configure_selinux")

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "calls").read_text().splitlines()[0] == "install -y policycoreutils"


def test_required_rhel_packages_are_installed(tmp_path: Path) -> None:
    _command(tmp_path, "dnf", 'echo "$*" >>"$CALL_LOG"')
    for command in ("python3", "openssl", "install", "useradd", "runuser", "systemctl", "restorecon"):
        _command(tmp_path, command, "exit 0")

    result = _run_function(tmp_path, "install_required_packages")

    assert result.returncode == 0, result.stderr
    packages = (tmp_path / "calls").read_text()
    assert packages.startswith("install -y ")
    for package in (
        "python3",
        "python3-pip",
        "openssl",
        "ca-certificates",
        "coreutils",
        "grep",
        "sed",
        "hostname",
        "shadow-utils",
        "util-linux",
        "systemd",
        "policycoreutils",
    ):
        assert package in packages.split()


def test_installers_install_system_packages_before_creating_the_service_user() -> None:
    for name in ("install-online.sh", "install-offline.sh"):
        script = (ROOT / "packaging" / name).read_text()
        assert script.index("install_required_packages") < script.index("id certify")


def test_online_installer_uses_local_project_source() -> None:
    script = (ROOT / "packaging" / "install-online.sh").read_text()

    assert 'pip install "$root"' in script
    assert "CERTIFY_VERSION" not in script
    assert "certify-server==" not in script


def test_updaters_use_transactional_common_flow() -> None:
    online = (ROOT / "packaging" / "update-online.sh").read_text()
    offline = (ROOT / "packaging" / "update-offline.sh").read_text()
    common = UPDATE_COMMON.read_text()

    assert 'certify_update "$root"' in online
    assert "sha256sum --check dist/SHA256SUMS" in offline
    assert "venv.new" in common
    assert "venv.previous" in common
    assert "from certify.api import create_app" in common
    assert "from certify.api import app" not in common
    assert common.index('pip" install') < common.index("systemctl stop certify")
    assert "systemctl is-active --quiet certify" in common
    assert 'mv "$previous" "$active"' in common


def test_wheelhouse_checksums_are_portable_and_bundle_is_created() -> None:
    script = (ROOT / "packaging" / "build-wheelhouse.sh").read_text()

    assert '(cd "$root" && sha256sum wheelhouse/*.whl dist/*.whl' in script
    assert "certify-update-" in script
    assert "README.md LICENSE packaging dist wheelhouse" in script
