"""
Sudo Service — approved command execution over SSH.

The gateway holds an SSH key that is authorized on the target agent machine.
A client submits the sudo command it wants to run, the gateway asks for Telegram
approval, and after approval executes it on the configured target via SSH.

Configuration lives under services.sudo. Request data cannot override the SSH
host/user/key; the gateway operator controls the target.
"""

import logging
import os
import shlex
import subprocess
from pathlib import PurePosixPath

from . import BaseService, service

log = logging.getLogger("auth-proxy.sudo")

SUDO_BINARIES = {"sudo", "/usr/bin/sudo", "/bin/sudo"}
SUDO_OPTIONS_WITH_VALUE = {"-A", "-b", "-C", "-c", "-D", "-g", "-h", "-p", "-R", "-r", "-T", "-t", "-U", "-u"}
DEFAULT_DENIED_COMMANDS = {
    "bash", "dash", "fish", "ksh", "sh", "tcsh", "zsh",
    "vi", "vim", "nvim", "nano", "emacs", "ed", "ex",
    "less", "more", "man", "view", "find", "xargs",
    "python", "python3", "perl", "ruby", "node", "php", "lua",
    "env", "script", "screen", "tmux", "su", "sudoedit",
}


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
    key_path = str(_service_config(config).get("ssh_key_path", "")).strip()
    if not key_path:
        raise RuntimeError("sudo service not configured: services.sudo.ssh_key_path is required")
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


def _strict_host_key_checking(config: dict) -> str:
    value = str(_service_config(config).get("strict_host_key_checking", "yes")).strip().lower()
    allowed = {"yes", "accept-new", "no"}
    if value not in allowed:
        raise RuntimeError(
            "sudo service misconfigured: services.sudo.strict_host_key_checking "
            f"must be one of {', '.join(sorted(allowed))}"
        )
    return value


def _parse_command(command: str) -> list[str]:
    try:
        argv = shlex.split(command, posix=True)
    except ValueError as e:
        raise ValueError(f"Invalid shell-style command syntax: {e}") from e
    if not argv:
        raise ValueError("'command' is required for 'run'")
    return argv


def _sudo_target_index(argv: list[str]) -> int:
    """Return index of the command sudo will execute after sudo options."""
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            return i + 1
        if not arg.startswith("-") or arg == "-":
            return i
        if arg in SUDO_OPTIONS_WITH_VALUE:
            i += 2
            continue
        if any(arg.startswith(f"{opt}=") for opt in SUDO_OPTIONS_WITH_VALUE):
            i += 1
            continue
        # Sudo also accepts combined short options. If one of the known options
        # that takes a value is combined with the value (e.g. -uroot), it does
        # not consume the next argument. Unknown/flag options are skipped.
        i += 1
    return len(argv)


def _basename(path: str) -> str:
    return PurePosixPath(path).name


def _list_from_config(value, default: set[str] | None = None) -> set[str]:
    if value is None:
        return set(default or set())
    if isinstance(value, str):
        return {v.strip() for v in value.split(",") if v.strip()}
    if isinstance(value, (list, tuple, set)):
        return {str(v).strip() for v in value if str(v).strip()}
    return set(default or set())


def _validate_argv(argv: list[str], config: dict | None = None) -> None:
    if argv[0] not in SUDO_BINARIES:
        raise ValueError("'command' must start with sudo")

    target_i = _sudo_target_index(argv)
    if target_i >= len(argv):
        raise ValueError("'command' must include a command for sudo to run")

    target_cmd = _basename(argv[target_i])
    svc = _service_config(config or {})
    allowed = _list_from_config(svc.get("allowed_commands"), default=None)
    denied = _list_from_config(svc.get("denied_commands"), default=DEFAULT_DENIED_COMMANDS)

    if allowed and target_cmd not in allowed:
        raise ValueError(f"sudo command '{target_cmd}' is not in services.sudo.allowed_commands")
    if target_cmd in denied:
        raise ValueError(f"sudo command '{target_cmd}' is denied by services.sudo.denied_commands")


def _remote_command(command: str, config: dict | None = None) -> str:
    argv = _parse_command(command)
    _validate_argv(argv, config)
    # SSH asks the remote account's shell to interpret the command string.
    # Re-joining parsed argv with shell quoting preserves argv semantics while
    # preventing metacharacters like ';', '&&', '|', '$()' from becoming syntax.
    return shlex.join(argv)


def _ssh_command(config: dict, remote_command: str) -> list[str]:
    return [
        "ssh",
        "-i", _ssh_key_path(config),
        "-p", _ssh_port(config),
        "-o", "BatchMode=yes",
        "-o", "PasswordAuthentication=no",
        "-o", "IdentitiesOnly=yes",
        "-o", f"StrictHostKeyChecking={_strict_host_key_checking(config)}",
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
        if "```" in command:
            raise ValueError("'command' must not contain triple backticks")
        if len(command) > 4000:
            raise ValueError("'command' is too long (max 4000 characters)")

        _validate_argv(_parse_command(command))

    @classmethod
    def execute(cls, action: str, data: dict, config: dict) -> dict:
        command = _normalize_command(data.get("command", ""))
        timeout = _timeout(config)

        try:
            safe_remote_command = _remote_command(command, config)
            ssh_cmd = _ssh_command(config, safe_remote_command)
        except (RuntimeError, ValueError) as e:
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
                "remote_command": safe_remote_command,
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
            "remote_command": safe_remote_command,
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
            "⚠️ *Command requested:*",
            "```",
            command,
            "```",
        ]
        if data.get("details"):
            lines.append(f"\n📝 *Details:*\n{_md_escape(data['details'])}")
        return "\n".join(lines)

    @classmethod
    def context(cls, action: str, data: dict) -> str:
        return _normalize_command(data.get("command", ""))
