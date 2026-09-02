---
name: generative-ui
description: Render bounded v1 or v2 native Loopdy cards when structured presentation is clearer than prose.
---

# Loopdy Generative UI

Use a Loopdy renderer when the user asks for a card, dashboard-like result, metrics, a bounded list, or a sequence of events. Keep normal prose when structured presentation adds no value.

The renderers are first-class model tools in the `loopdy` toolset. If the exact
renderer is visible in the current tool list, call it directly. If Hermes has
progressively disclosed plugin tools and that renderer is absent, use the
official `tool_search`, `tool_describe`, and `tool_call` bridge to find and
invoke that exact renderer. Do not route a visible renderer through the bridge,
wrap it in another tool, or invent a replacement.

## Choose the delivery path first

### A. Inline card in the active chat

Use this path when the card answers the message in the conversation currently
open in Loopdy. Call the renderer on the active conversation response path. Its
validated result is published back to that chat and remains part of that turn.
Do not use the notification channel just to answer the current chat. Do not
address `loopdy:all`, a device, or a group unless the user separately asked for
a proactive notification.

Example instruction for an active weather chat:

> Fetch the forecast and call `loopdy_render_weather_forecast` for this response.
> Keep the card in this active conversation; do not send a Loopdy notification.

### B. Proactive or scheduled card in Agent Inbox/Home

No script or separate notification API is required. For an ordinary channel
message or a scheduled task delivered to `loopdy`, call exactly one registered
`loopdy_render_*` tool and use its validated returned envelope as the complete final channel-delivery payload. Return the envelope verbatim: no Markdown fence,
introductory sentence, trailing explanation, or second prose response. Hermes'
official platform boundary gives the Loopdy adapter only that final text plus
ordinary delivery metadata such as a cron `job_id`; it does not separately pass
the earlier tool result. An inline renderer result does not auto-forward to
Agent Inbox/Home. Loopdy validates the delivered envelope again before storing
or pushing a native card. Invalid or mixed content safely remains a text update.

Never script or reconstruct a renderer envelope. Call the official renderer
and forward its exact validated return value. Do not manually rebuild JSON from
the visual result or assume a prior inline tool call will be attached later.

For a scheduled task, choose the `loopdy` delivery channel and include this in
the task instructions:

> Call `loopdy_render_summary` with the result, then make the exact returned
> envelope your complete final response. Do not wrap it in Markdown or add prose.

For an ordinary channel send, pass the exact complete envelope already returned
by the renderer as the message. The transport shape is:

```bash
hermes send --to loopdy:all '<exact validated envelope returned by loopdy_render_*>'
```

The placeholder is not an instruction to hand-author JSON. If there is no exact
renderer return value to send, deliver a normal text notification instead.

For current weather or forecast requests, fetch the current data and then call
`loopdy_render_weather_forecast` directly with the strict v2 payload below when
a card would make the result easier to use. Do not stop at a prose-only forecast
when the native weather card is relevant.

Choose one renderer. The original v1 tools remain compatible:

- `loopdy_render_summary` for a title and short body.
- `loopdy_render_metrics` for up to 20 labeled scalar values.
- `loopdy_render_list` for up to 20 short items.
- `loopdy_render_timeline` for up to 20 ordered steps.

Use v2 for typed current-data and interactive cards:

- `loopdy_render_weather_forecast`
- `loopdy_render_sports_game`
- `loopdy_render_stock_quote`
- `loopdy_render_chart`
- `loopdy_render_dashboard`
- `loopdy_render_form`

V2 calls use `schema: "loopdy.generative_ui"`, `version: 2`, the matching
component, and the exact strict tool schema. Current-data cards require source
timestamps and freshness provenance. The renderer derives `age_seconds` from
those timestamp facts, so it may be omitted (or supplied as stale model
metadata). Forms are bound by the host to the exact
profile and session. After rendering a form, call
`loopdy_await_form_response` with only its server-generated `request_id`; do
not invent an endpoint, route, command, URL, or action target.

Every v1 call uses `version: 1`, the matching `component`, and an optional short `title`. Do not add URLs, HTML, styles, routes, actions, or executable content.

## Examples

Summary:

```json
{"version":1,"component":"summary","title":"Build status","body":"All verification checks passed."}
```

Metrics:

```json
{"version":1,"component":"metrics","title":"Task checks","metrics":{"Passed":18,"Failed":0,"Duration":"4m 12s"}}
```

List:

```json
{"version":1,"component":"list","title":"Next steps","items":["Review the diff","Run the device smoke test","Prepare release notes"]}
```

Timeline:

```json
{"version":1,"component":"timeline","title":"Deployment","steps":["Build completed","Checks passed","Ready for approval"]}
```
