# Skills and capability controls (management contract 2)

## Release coupling

Deploy this committed Loopdy plugin **before** shipping the corresponding app.
The previously installed host only implemented `skills_tools.list`; an app-only
release cannot repair editing, creation or import. A host restart to activate a
plugin deployment is a separate operator-authorized release action. This source
change does not install, restart, or modify an installed Hermes runtime.

`skills_tools.list` retains `agentId`, `skills`, `plugins`, and `mcpServers` and
adds:

- `management: {version: 2, read: Bool, create: Bool, update: Bool, import: Bool}`
- `tools`: supported Hermes **toolsets**, with `id`, `name`, `description`,
  `platform`, `enabled`, and `toolCount`
- `toolsNotice`: a bounded message when the optional toolset catalog is unavailable

The app keeps legacy lists readable. Missing/unknown management versions show an
explicit host-update notice instead of attempting unsupported edits. Create and
import taps explain that requirement. Read/save/import errors are visible in the
current sheet or an alert, not hidden below a long catalog. The V2 appearance flag
is supplied by the app foundation (`EnvironmentValues.loopdyUIV2Enabled`, default
false); the original drawer and catalog layout remain available with it off.

## Authenticated operation contract

All operations continue through the existing signed, account-encrypted,
request-bound `workspace.request` transport. There is no new listener, raw config
editor, generic RPC, arbitrary command runner, credential payload, or alternate
authentication path. A paired authorized endpoint already has the workspace
management authority. Identifiers are scoped to the explicitly selected profile.

The existing operation names are extended with **disjoint, exact payloads**;
there is no change to the operation allowlist:

| Operation | Payload | Result |
|---|---|---|
| `skills_tools.list` | `{agentId}` | Catalog plus management metadata |
| `skills_tools.get` | `{agentId, skillId}` | Existing SKILL.md content + SHA-256 |
| `skills_tools.create` | `{agentId, name, content, category?}` | Read-back skill document |
| `skills_tools.import` | `{agentId, kind, dataBase64, category?}` | Read-back skill document; kind is `skillMd` or `zip` |
| `skills_tools.update` | `{agentId, skillId, content, expectedSha256}` | Read-back document after revision check |
| `skills_tools.get` | `{agentId, capabilityKind, capabilityId}` | `{agentId, control}` |
| `skills_tools.update` | `{agentId, capabilityKind, capabilityId, enabled, expectedRevision, confirmed: true}` | `{agentId, control}` read back after saving |

`capabilityKind` is exactly `skill`, `plugin`, `mcpServer`, or `toolset`.
`control` contains `kind`, `id`, `enabled`, `canToggle`, `reason`, `scope`,
`activation`, and `revision`. The revision binds the profile, typed target,
reported state, scope, activation disclosure and lock reason. Extra keys,
non-boolean `enabled`, absent confirmation, unknown/ambiguous catalog targets,
locked targets, or stale revisions are rejected. No caller-provided path or
configuration document reaches a host writer.

The UI first loads the selected target, then confirms the exact profile, target,
scope and activation semantics. It does not optimistically flip the row. The
host rereads before writing and after writing; the client validates the returned
typed coordinate and requested state. A timeout or ambiguous failure never
automatically retries a write: refresh first. Account/profile reset invalidates
pending control state and receipts, as it does skill documents.

## Supported Hermes services and truthful scope

Research basis: current official [Skills](https://hermes-agent.nousresearch.com/docs/user-guide/features/skills),
[MCP](https://hermes-agent.nousresearch.com/docs/user-guide/features/mcp), and
[Plugin](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins)
documentation, together with the installed Hermes source (read-only reference).

| Kind | Existing Hermes service | Meaning / constraints |
|---|---|---|
| Skill | `hermes_cli.web_routers.skills.toggle_skill(SkillToggle(...), profile=...)` | Profile-global disabled policy. Platform-specific disabled lists may still apply. Essential skills are locked using Hermes' `ESSENTIAL_SKILLS` policy. |
| MCP server | `hermes_cli.web_routers.mcp.set_mcp_server_enabled(name, MCPEnabledToggle(...), profile=...)` | Persists the existing server's `enabled` setting without returning credentials or server commands. New session or host-managed MCP reload; no reload is performed by Loopdy. |
| Standalone plugin | `hermes_cli.plugins_cmd.dashboard_set_agent_plugin_enabled(name, enabled=...)` under the public context-local Hermes home override | The same service used by Hermes' authenticated dashboard. Persists plugin allow/deny policy and the service's associated toolset changes. Host restart required; no running plugin is unloaded here. |
| Toolset | `hermes_cli.web_routers.tools.toggle_toolset(name, ToolsetToggle(...), profile=...)` | The host's configuration platform, usually **CLI**, sometimes a platform-specific toolset. This is not a claim to change the active Loopdy conversation. Enabling can invoke Hermes' install-on-enable provider setup; the confirmation discloses that behavior. |

The catalog uses Hermes' per-home plugin manager without forcing discovery or
executing plugins to render a screen. Thus it lists plugins **already discovered
by that profile's runtime**, not an invented filesystem inventory. An inactive
profile whose manager has not been populated can have no plugin rows yet.
Configured standalone enablement is reread from Hermes' configuration, not the
manager's stale pre-restart loaded flag. Other provider state remains host-reported.

Locked items include the Loopdy control integration, non-standalone provider and
platform plugins, ambiguous bare plugin identities, and qualified plugins blocked
by an additional legacy bare-name deny rule. Otherwise canonical qualified keys
are passed unchanged to the host's supported plugin service. Missing APIs produce a supported-host
upgrade reason. Individual compiled tool implementations are not SKILL.md files:
this UI edits skill documents and the configuration units Hermes actually exposes.
It deliberately does not offer raw tool code, arbitrary MCP configuration, secret
editing, per-tool MCP filter editing, or provider selection.

## Skill document and ZIP safety

Existing official skill content/create/update handlers remain the backing
services. The existing ZIP path is retained: one manifest; 1.5 MB compressed,
4 MB expanded, 64 file and 512 KB per-file limits; common-root validation;
case-folded duplicate and traversal rejection; support-directory allowlist;
exclusive supporting-file creation; complete-tree security scan and rollback.
Encrypted and special-file ZIP members are now explicitly rejected as well.
The phone reads a bounded amount before uploading rather than mapping an
arbitrarily large selected file. Host errors do not reflect raw config, paths,
or security-scan excerpts to the wire.

The SKILL.md update retains its expected SHA-256 precondition and Link-controller
serialization, rereads the document inside that operation, and rejects a
post-write content mismatch. The client also checks content against the returned
SHA-256 and binds saves to the actual displayed document. Existing ZIP installation
uses Hermes' skill-manager/profile helper implementation and therefore still
requires the compatible host counterpart; an app update alone cannot provide it.

## Known host concurrency boundary

The inspected public skill/config mutation APIs do **not** accept an atomic
cross-process expected revision. Link serializes its own capability changes and
skill updates and verifies readback, but cannot promise transactional CAS against
simultaneous CLI/dashboard/agent writes from another process. In particular the
plugin service performs several config writes. This implementation does not
monkeypatch private core locks/globals, create shadow config, or claim that a
plugin-local lock fixes external writers. A stronger guarantee requires an
upstream Hermes compare-and-set/transaction service. Avoid simultaneous host
configuration edits while confirming a mobile change.

## Integration-owner validation (not executed in this source lane)

The parent owns builds and tests. Cover legacy/missing capability responses,
exact request shapes, locked Loopdy/essential/ambiguous/provider targets,
profile/account changes during suspended reads and writes, stale revision and
unconfirmed write failures, disabled-item readback, platform disclosure, genuine
SKILL.md create/edit/import, hostile ZIP rejection/rollback, V1/V2 navigation,
custom themes, VoiceOver, Dynamic Type and iPad layouts. Existing fixture clients
without management metadata intentionally behave as legacy read-only hosts;
new editor/control fixtures must explicitly advertise the contract they model.
