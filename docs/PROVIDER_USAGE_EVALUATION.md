# Provider usage discovery evaluation

## Initial take

The request is to let Loopdy discover which AI providers are configured on the
paired Hermes host, then show each provider's current token or credit usage in a
Liquid Glass modal opened from the bottom anchor drawer.

Provider discovery is plausible as a host-side plugin feature: the plugin can
look for bounded, non-secret configuration signals for tools such as Claude
Code, Codex, OpenCode, and GitHub Copilot CLI. Current usage is the harder part.
Those tools do not expose a common local, stable, user-authorized usage API, and
some usage or billing data is account-scoped rather than host-scoped.

## Feasibility score

**2 / 5**

- Discovery can be built carefully with allowlisted config markers and no secret
  values crossing Loopdy Link.
- Accurate live usage would require provider-specific APIs, local ledger formats,
  or CLI commands that are not uniform, may change, and may expose sensitive
  account or transcript metadata if handled incorrectly.
- The plugin repository can expose a safe backend contract, but the Liquid Glass
  modal itself belongs in the native app and is outside this repository.

## User experience score

**4 / 5**

- A single modal for provider availability and remaining usage would be valuable
  and understandable, especially when multiple CLI providers are installed.
- The mockup's card layout maps well to a compact provider summary.
- The experience would be poor if the modal shows inaccurate limits or stale
  credit values, so the UI should distinguish "configured", "usage available",
  and "usage unavailable" states instead of guessing.

## Findings

**No Build for the full feature in this repository right now.**

The plugin should not ship a fake or inferred usage meter. A safe implementation
needs a documented provider-by-provider contract for where usage comes from,
whether it is local or remote, how user authorization works, and what values may
cross the encrypted Link boundary. Without that contract, the repository can
only support partial discovery, while the requested Liquid Glass presentation is
implemented in the app.

Recommended next step: design a minimal backend contract that returns only
bounded provider names, installed/configured status, usage source, last updated
time, and optional numeric usage fields when a provider exposes an explicit
supported source. Then build the native modal against that contract.
