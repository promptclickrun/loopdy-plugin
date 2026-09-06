# Agent-controlled companion reactions

Status: queued, documentation-only draft. Implementation is intentionally deferred.
This document proposes a contract; no tool or capability described below is available from this PR.

## Outcome

Let an agent briefly express an authored reaction through the companion in its current Loopdy conversation without adding a message bubble. Keep ordinary task and voice state truthful.

```text
agent tool call
  -> validate reaction + authenticated current-session ownership
  -> capability-negotiated encrypted Link event
  -> native companion reaction
  -> expiry returns control to real activity state
```

## Proposed plugin scope

- Add a supported Hermes plugin tool, tentatively `loopdy_pet_react`, using public tool registration only. Do not alter Hermes core, gateway internals or configuration.
- Accept a finite reaction vocabulary: `hmm`, `question`, `zzz`, `aha`, `smitten`, `oh`, `yes`, `nope`, `meh`, `grr`, `wow`, `woozy`. Exact schema and timing limits remain to be finalized with the app implementation.
- Resolve profile, account, host, session and active turn from trusted execution context. Do not accept arbitrary destination IDs from the model. Fail closed when ownership is ambiguous or context is outside an eligible Loopdy conversation.
- Add a small versioned event with stable event identity, ordering and bounded lifetime. Negotiate capability before sending; preserve older clients' strict envelopes.
- Rate-limit reactions, bound queues, deduplicate repeated calls/events, and discard expired or cancelled-turn effects. No delayed replay on reconnection or history hydration.
- Return honest outcomes: accepted for delivery is not proof of display. Unsupported client, unavailable route, suppressed/offscreen pet, and failed delivery must not be represented as rendered success. Define any display acknowledgment explicitly with the app.
- Decorative reactions never grant user approval, imply verified task completion, or override real microphone/audio indicators. Tool calls may remain in normal activity/audit history; no additional conversational message is required.
- Keep exported code and documentation generic. No companion artwork, meshes, textures, private application sources or household context belong in this public repository.

## Deferred implementation checklist

- [ ] Finalize shared schema, lifecycle/priority rules and capability negotiation with the app PR.
- [ ] Prove trusted tool-context routing through the supported Hermes plugin API.
- [ ] Implement validation, routing and bounded ephemeral event delivery.
- [ ] Test invalid names/types, wrong owner, missing context, unsupported clients, repeated calls, rate limits, expiry, cancellation and reconnect.
- [ ] Exercise the composed tool-to-Link-to-native path, not only a mocked sender.
- [ ] Reconcile standalone and app-vendored plugin changes without importing unrelated work.
- [ ] Update tool usage guidance to use reactions sparingly and semantically.

## Delivery boundary

This PR queues future work only. It does not install or activate a plugin, restart services, publish a release, or change the app. Coordinate compatible app and plugin deployment separately after implementation and explicit approval.
