# Changelog

## 2026.10.23.05
System tools now work on hosts with no stacks folder (they start in the login folder). `server_hosts` says "connection ok" and "docker not installed" for hosts without docker.

## 2026.10.23.04
Removed the fallback login. Use a key or an SSH password. The SSH password is also used for sudo when sudo asks, and it can never leak into file data.

## 2026.10.23.03
Key logins no longer fail on a new host. A new host key is trusted once (like password logins). `SERVER_MCP_SSH_STRICT=true` turns this off.

## 2026.10.23.02
Example config and README now use `uvx` (the old `python -m server_mcp` form needed the folder on the path).

## 2026.10.23.01
First release of server-mcp, the full server version of a Docker-only tool.

- Docker tools: containers, stacks, images, volumes, networks, build, run, copy, and `docker_cli` for anything else.
- System tools: `server_info`, `server_service`, `server_journal`, `server_packages`, `server_processes`, `server_power`, `server_run`.
- File tools on any path, with `as_root` for sudo.
- Preview then confirm: every change shows exactly what will happen (file edits show a diff). It runs only after a yes and a repeat call with `confirm=true`.
- Secrets are hidden in all output. Files with keys and passwords are never read.
