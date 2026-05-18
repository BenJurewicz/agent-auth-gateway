"""
Sudo Service — approved sudo command execution over SSH.

The gateway holds an SSH key that is authorized on the target agent machine.
A client submits the exact sudo command it wants to run, the gateway asks for
Telegram approval, and after approval executes that exact command on the
configured target via SSH.

Configuration lives under services.sudo. Request data cannot override the SSH
host/user/key; the gateway operator controls the target.
"""

import logging
import os
import shlex
import subprocess

from . import BaseService, service

log = logging.getLogger("auth-proxy.sudo")


def _md_escape(value) -> str:
    text = str(value)
    for char in ("\\", "_", "*", "`", "[", "]"):
        text = text.replace(char, f"\\{char}")
    return text


def _md_code(value, default: str = "?") -> str:
    if value is None:
        value = default
    return f"`{_md_escape(value)}`"


def _service_config(config: dict) -> dict:
    return config.get("services", {}).get("sudo", {}) or {}


def _timeout(config: dict) -> int:
    try:
        return max(1, int(_service_config(config).get("timeout", 300)))
    except (TypeError, ValueError):
        return 300


def _target(config: dict) -> str:
    svc = _service_config(config)
    host = str(svc.get("host", "")).strip()
    user = str(svc.get("user", "")).strip()
    if not host:
        raise RuntimeError("sudo service not configured: services.sudo.host is required")
    return f"{user}@{host}" if user else host


def _ssh_key_path(config: dict) -> str:
    key_path = str(_service_config(config).get("ssh_key_path", "~/.ssh/id_ed25519"))
    return os.path.expanduser(key_path)


def _ssh_port(config: dict) -> str:
    port = _service_config(config).get("port", 22)
    try:
        n = int(port)
    except (TypeError, ValueError) as e:
        raise RuntimeError("sudo service misconfigured: services.sudo.port must be an integer") from e
    if n < 1 or n > 65535:
        raise RuntimeError("sudo service misconfigured: services.sudo.port must be 1-65535")
    return str(n)


def _ssh_command(config: dict, remote_command: str) -> list[str]:
    return [
        "ssh",
        "-i", _ssh_key_path(config),
        "-p", _ssh_port(config),
        "-o", "BatchMode=yes",
        "-o", "PasswordAuthentication=no",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        _target(config),
        remote_command,
    ]


def _normalize_command(value) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


@service("sudo")
class SudoService(BaseService):
    valid_actions = {"run"}

    @classmethod
    def validate(cls, action: str, data: dict) -> None:
        if action not in cls.valid_actions:
            raise ValueError(
                f"Unsupported sudo action: '{action}'. Use: {', '.join(cls.valid_actions)}"
            )

        command = _normalize_command(data.get("command", ""))
        if not command:
            raise ValueError("'command' is required for 'run'")
        if "\x00" in command:
            raise ValueError("'command' must not contain NUL bytes")
        if len(command) > 4000:
            raise ValueError("'command' is too long (max 4000 characters)")

        # This service is intentionally scoped to sudo operations only. The
        # gateway still asks for approval, but enforcing the prefix prevents it
        # from becoming a generic remote shell by accident.
        first = shlex.split(command, posix=True)[0] if command else ""
        if first not in {"sudo", "/usr/bin/sudo", "/bin/sudo"}:
            raise ValueError("'command' must start with sudo")

    @classmethod
    def execute(cls, action: str, data: dict, config: dict) -> dict:
        command = _normalize_command(data.get("command", ""))
        timeout = _timeout(config)

        try:
            ssh_cmd = _ssh_command(config, command)
        except RuntimeError as e:
            return {"success": False, "output": str(e), "exit_code": -1}

        target = ssh_cmd[-2]
        log.info("Running approved sudo command on %s", target)

        try:
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as e:
            stdout = e.stdout or ""
            stderr = e.stderr or ""
            output = (stdout + ("\n" if stdout and stderr else "") + stderr).strip()
            if output:
                output += "\n"
            output += f"Command timed out after {timeout}s"
            return {
                "success": False,
                "output": output,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": -1,
                "command": command,
                "target": target,
            }

        stdout = result.stdout or ""
        stderr = result.stderr or ""
        output = (stdout + ("\n" if stdout and stderr else "") + stderr).strip()
        return {
            "success": result.returncode == 0,
            "output": output,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": result.returncode,
            "command": command,
            "target": target,
        }

    @classmethod
    def approval_text(cls, action: str, data: dict, request_id: str) -> str:
        command = _normalize_command(data.get("command", ""))
        lines = [
            "🔐 *Auth Proxy — Sudo over SSH*",
            f"`{request_id[:16]}…`",
            "",
            "📋 *Action:* `run approved sudo command`",
            "🖥 *Target:* configured gateway SSH target",
            "",
            "⚠️ *Command to run exactly:*",
            "```",
            _md_escape(command),
            "```",
        ]
        if data.get("details"):
            lines.append(f"\n📝 *Details:*\n{_md_escape(data['details'])}")
        return "\n".join(lines)

    @classmethod
    def context(cls, action: str, data: dict) -> str:
        return _normalize_command(data.get("command", ""))
