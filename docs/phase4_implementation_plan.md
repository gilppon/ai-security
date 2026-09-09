# Phase 4 + Resource Authorization Plan

## Scope

Implement authorization only for tools, MCP calls, filesystem paths, and network destinations. Do not execute tools, open files, send network requests, or start processes.

## Pipeline

`Authorization SecurityEvent -> Normalize -> Identity/Manifest/Argument/Resource checks -> Risk -> Policy -> Decision -> Audit`

## Controls

1. Server-owned tool registry with strict argument schemas and default deny.
2. Verified agent identity supplied only through internal trusted integration; public request fields cannot grant identity.
3. MCP manifests and permission grants owned by server configuration; detect unknown tools, description injection, and scope escalation.
4. Filesystem paths resolved before final authorization; enforce operation grants, allowed roots, symlink containment, and sensitive-path denial.
5. Network URLs parsed without credentials; enforce HTTPS, hostname allowlist, DNS resolution, all-address public-IP checks, metadata denial, and redirect reauthorization.
6. Resource decisions and parent Tool/MCP decisions each generate auditable SecurityEvents.
7. Structured reason codes; internal errors fail closed at risk 100.

## Validation

- Tool existence, verified identity, agent permission, schema types, required/extra arguments, and resource denial propagation.
- MCP server/tool declaration, scope permissions, capability escalation, description injection, and underlying Tool Firewall propagation.
- Workspace read/write, path traversal, symlink escape, `.ssh`, `.aws`, `.env`, PEM/key, credentials files.
- Public HTTPS, disallowed scheme/host, localhost, IPv4 private/link-local/metadata, IPv6 loopback/ULA/link-local, mixed public/private DNS, redirect targets.
- API default deny, audit redaction, full regression, compile, and security scans.
