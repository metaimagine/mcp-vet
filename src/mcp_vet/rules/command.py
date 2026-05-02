from __future__ import annotations

from collections.abc import Iterable

from mcp_vet.models import Finding, MCPServer, Severity


SHELL_COMMANDS = {"sh", "bash", "zsh", "cmd", "powershell", "pwsh"}
SHELL_FLAGS = {"-c", "/c", "-command"}
CONTAINER_COMMANDS = {"docker", "podman"}
DOCKER_SOCKET_PATHS = {"/var/run/docker.sock", "/run/docker.sock"}


def check_command(server: MCPServer) -> Iterable[Finding]:
    command = (server.command or "").lower()
    args = [arg.lower() for arg in server.args]
    if command in SHELL_COMMANDS and any(arg in SHELL_FLAGS for arg in args):
        yield Finding(
            id="command.shell-wrapper",
            title="Server launches through a shell wrapper",
            severity=Severity.HIGH,
            server=server.name,
            evidence=f"{server.command} {' '.join(server.args)}",
            remediation="Replace shell wrappers with a direct executable and fixed arguments.",
            confidence=0.95,
        )
    if command in {"npx", "uvx"} and not any(_looks_pinned(arg) for arg in server.args):
        yield Finding(
            id="command.unpinned-package",
            title="Server appears to run an unpinned package",
            severity=Severity.MEDIUM,
            server=server.name,
            evidence=f"{server.command} {' '.join(server.args)}",
            remediation="Pin the server package version or use a reviewed local checkout.",
            confidence=0.75,
        )
    if command in CONTAINER_COMMANDS and "run" in args:
        if any(_is_privileged_container_arg(arg) for arg in args):
            yield Finding(
                id="command.privileged-container",
                title="Server runs a privileged container",
                severity=Severity.HIGH,
                server=server.name,
                evidence=f"{server.command} {' '.join(server.args)}",
                remediation=(
                    "Remove --privileged and grant only the specific mounts, devices, "
                    "or capabilities this MCP server needs."
                ),
                confidence=0.9,
            )
        for mount_spec in _iter_mount_specs(server.args):
            if _mount_exposes_docker_socket(mount_spec):
                yield Finding(
                    id="command.docker-socket-mount",
                    title="Server mounts the Docker control socket",
                    severity=Severity.HIGH,
                    server=server.name,
                    evidence=mount_spec,
                    remediation=(
                        "Do not mount the Docker socket into agent-controlled tools; "
                        "use a narrower service account or reviewed wrapper instead."
                    ),
                    confidence=0.95,
                )
            if _mount_exposes_host_root(mount_spec):
                yield Finding(
                    id="command.host-root-bind-mount",
                    title="Server bind-mounts the host root filesystem",
                    severity=Severity.HIGH,
                    server=server.name,
                    evidence=mount_spec,
                    remediation=(
                        "Do not mount the host root into an MCP server container; "
                        "mount the narrowest required directory, preferably read-only."
                    ),
                    confidence=0.9,
                )


def _looks_pinned(arg: str) -> bool:
    return "@" in arg and not arg.startswith("@")


def _is_privileged_container_arg(arg: str) -> bool:
    normalized = arg.lower()
    return normalized == "--privileged" or normalized == "--privileged=true"


def _iter_mount_specs(args: list[str]) -> Iterable[str]:
    for index, arg in enumerate(args):
        normalized = arg.lower()
        if normalized in {"-v", "--volume", "--mount"} and index + 1 < len(args):
            yield args[index + 1]
        elif normalized.startswith("--volume=") or normalized.startswith("--mount="):
            yield arg.split("=", 1)[1]
        elif normalized.startswith("-v") and len(arg) > 2:
            yield arg[2:]


def _mount_exposes_docker_socket(mount_spec: str) -> bool:
    return any(socket_path in mount_spec for socket_path in DOCKER_SOCKET_PATHS)


def _mount_exposes_host_root(mount_spec: str) -> bool:
    return _mount_source(mount_spec) == "/"


def _mount_source(mount_spec: str) -> str | None:
    if "=" in mount_spec and "," in mount_spec:
        fields = {}
        for part in mount_spec.split(","):
            key, separator, value = part.partition("=")
            if separator:
                fields[key.strip().lower()] = value.strip()
        return _normalize_mount_source(fields.get("source") or fields.get("src"))

    source, separator, _target = mount_spec.partition(":")
    if separator:
        return _normalize_mount_source(source)
    return None


def _normalize_mount_source(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if stripped == "/":
        return "/"
    return stripped.rstrip("/")
