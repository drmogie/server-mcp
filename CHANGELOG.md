# Changelog

## 2026.10.23.01
First release of server-mcp, the full server version of a Docker-only tool.

- Docker tools: containers, stacks, images, volumes, networks, build, run, copy, and `docker_cli` for anything else.
- System tools: `server_info`, `server_service`, `server_journal`, `server_packages`, `server_processes`, `server_power`, `server_run`.
- File tools on any path, with `as_root` for sudo.
- Preview then confirm: every change shows exactly what will happen (file edits show a diff). It runs only after a yes and a repeat call with `confirm=true`.
- Fallback SSH login (user, password and/or key) used when the main login is refused.
- Secrets are hidden in all output. Files with keys and passwords are never read.
