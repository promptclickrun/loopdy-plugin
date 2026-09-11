# Direct streaming and live voice

Loopdy keeps Hermes as the execution and canonical-history owner. The native app uses bounded session pages and a separate disposable live overlay. Full tool content is retrieved only when you open its complete-content reader.

## Routes

A paired host can expose the plugin-owned listener through a private Tailscale HTTPS origin. Configure the plugin with `hermes loopdy direct configure --origin https://HOST:PORT --port LOOPBACK_PORT --enabled`, then restart Hermes when ready. In the app, select that host and use its optional Direct Connection section to verify and enroll the route. The account-paired identity is required; Tailscale membership alone is not authorization.

Direct requests reuse existing chat, workspace, attachments, approvals, voice and device-tool interfaces. A connection failure before a request can use Link. An ambiguously delivered command is not automatically repeated through another route. Direct admission uses a fresh device lifecycle lease from the account service, so this is not indefinite cloud-independent authorization.

State-backed relay clients explicitly negotiate `state-backed-presentation-v1`. Recoverable drafts and activity do not accumulate as an offline animation backlog for those recipients. Reliable commands, results, attachments and legacy clients retain their existing delivery contract. A slow subscriber receives a reset and reconnects without blocking another phone. Transient sequence tracking never advances the reliable replay watermark.

## Voice

Live voice defaults to **Codex subscription** (`gpt-live-1-codex`). The plugin uses Hermes-managed subscription credentials; the phone receives no bearer token. Native WebRTC carries audio directly to the provider while authenticated Loopdy messages carry setup, captions and job controls. The provider sideband is connected before the answer SDP is returned.

Every delegated task has its own Hermes conversation, durable job identity and owner/revision checks. Tasks can finish independently and return concise, redacted results. Muting, barge-in and ending the call do not cancel accepted work. Cancel targets one job explicitly. Unknown admission or control outcomes are reconciled rather than resubmitted.

An explicitly selected API-key mode uses the distinct public `gpt-live-1` protocol and the host's configured `OPENAI_API_KEY`. It may incur separate usage charges. Subscription errors never select it automatically. Turn-based voice remains an explicit alternative.

## Security and compatibility

The plugin does not modify Hermes core or start a second model-execution service. All jobs use supported platform-adapter ingress and lifecycle/approval/clarification callbacks. iPhone device tools remain opt-in and require the existing verified host-context capability; unsupported hosts do not gain authority from a voice transcript or device identifier.

Per-session protected content files replace repeated whole-catalog transcript writes. Migration retains the old snapshot until the new manifest commits. Failed writes preserve the prior committed content. Account erasure removes all scoped revisions.

## Validation boundaries

Automated verification covers state paging, content reconstruction, cache saturation, owner changes, independent jobs, subscription wire formatting, relay recipient isolation, native audio offer/answer handling and simulator UI. The subscription endpoint was exercised using actual Hermes-managed authentication with native SDP. Physical-device testing is not required for this release. Network conditions, Bluetooth/audio hardware and subjective conversational quality still warrant normal beta testing.
