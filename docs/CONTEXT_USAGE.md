# Context usage reporting

Loopdy consumes Hermes's public `post_api_request` usage summary. The observer stores only bounded numeric token fields with session/model correlation, not prompts, response text, credentials, or raw provider payloads.

```text
provider -> Hermes canonical usage -> post_api_request
                                        |
                             bound session/model snapshot
                                        |
                          session.context + reconnect snapshot
```

The existing client fields describe the **latest request**, not cumulative account usage:

| Field | Meaning |
| --- | --- |
| `contextUsed`, `inputTokens` | Full prompt input, including cached tokens |
| `outputTokens` | Output tokens |
| `cachedTokens` | Cache-read tokens |
| `totalTokens` | Full input plus output |

A real zero is retained. Missing or malformed latest usage is omitted rather than invented or summed with older requests. Duplicate request IDs and older same-turn request numbers cannot roll counts backward. Session/model scope is exact; chat alias bindings are preserved. Session reset and broker detach clear usage.

Cache writes and reasoning tokens are tracked by Hermes, but the current native client schema does not expose separate rows for them. This change does not expand that schema or claim account-wide quota reporting. Historical missing values are not reconstructed after a process restart.

## Verification

Focused usage, context, registration, activity, and wire-contract tests pass. The old test that injected a fictional `agent.token_usage` object now exercises a real broker with the supported hook shape.

A synthetic live repeated-prefix check passed through an installed Copilot adapter, unmodified Hermes, the public hook, this projector, and the existing `session.context` serializer. The second request reported 13,056 prompt tokens, 9 output tokens, 13,053 cache-read tokens, and 13,065 total tokens. The projected fields matched exactly. Its capture-only output sink did not send to a paired app; installation and visual activation remain separate deployment checks.

No Hermes private runtime mutation, provider-specific allowlist, raw prompt logging, or automatic service restart is introduced.
