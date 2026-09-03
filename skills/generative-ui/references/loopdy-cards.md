# Loopdy Cards v1

Loopdy Cards are a bounded, display-only native card language for new static compositions. Call the direct `loopdy_render_card` tool when it is visible; use the official progressive-disclosure bridge only when it is not. Typed v2 cards remain preferred for already-supported polished use cases until the generic renderer reaches visual parity.

## Safety and lifecycle

For this release, `data_sources` must be an empty array. Put current or computed values directly in the card payload before calling the renderer. The app does not fetch card data from the network. Cards contain no downloaded code, HTML, WebViews, authenticated requests, credentials, or secrets. The card is display-only; use the typed form renderer for input.

## Finite component catalog

Every element has a unique ID, a catalog `type`, bounded `props`, and legal `children`. There are no arbitrary modifiers, colors, fonts, frames, coordinates, or symbols.

| Component | Use | Children |
|---|---|---|
| `card` | titled native container | yes |
| `vstack` | vertical layout | yes |
| `hstack` | horizontal layout | yes |
| `grid` | adaptive two/three-column layout | yes |
| `text` | label, paragraph, caption, heading | no |
| `metric` | prominent labeled value and optional trend | no |
| `badge` | short semantic status | no |
| `progress` | bounded value from zero through max | no |
| `chart` | line, area, or bar series | no |
| `table` | bounded columns and rows | no |
| `list` | reserved for a later live-data release; use the typed list renderer now | one template child |
| `divider` | native divider | no |
| `spacer` | bounded spacing token | no |
| `image` | bundled SF Symbol or app asset | no |

Colors are semantic: `primary`, `secondary`, `positive`, `warning`, `negative`, `accent`, `neutral`. Spacing and typography are finite tokens. Image names are an app-owned allowlist.

## Values and expressions

A value must be a literal in this static-only release:

```json
{"literal":"Open"}
```

JSON Pointer bindings and finite expressions remain reserved for the later live-data release. They cannot be used when `data_sources` is empty.

Format styles are `text`, `integer`, `number`, `currency`, `percent`, `date`, `time`, and `relative_date`, and are locale-aware in the app. Tables, charts, text, and the document have strict finite limits enforced by both plugin and app.

## Worked shapes

### Build health

Use a `grid` of literal `metric`, `progress`, and `badge` values to summarize results already obtained by the agent.

### Project status

Use a `vstack` or `hstack` with literal `text`, `metric`, and `badge` values. Use the typed list or timeline renderer when the presentation requires repeated rows.

### Comparison table

Use a bounded `table` whose columns and rows are fully embedded in the payload.

The original v1 summary/metrics/list/timeline tools and typed v2 renderers remain compatible. Choose one renderer and return its exact validated envelope without Markdown or extra prose.
