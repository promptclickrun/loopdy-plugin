# Agent board: Feed, Ideas, Goals, Activity and Approvals history

The bighelp app shows each agent's board next to its chat. The plugin stores it per
profile in `<profile home>/plugin-data/loopdy/board.sqlite3`.

## Writing (agents only)

The `bighelp_board` tool (toolset `loopdy`) publishes Feed posts (`post`), Ideas
(`idea`) and Goals (`goal`, `update_goal`), and can `list` or `remove` items. Local
images are copied into `board-media/` at publish time; only those copies (PNG, JPEG,
GIF, WebP, HEIC, 8 MB max) are ever served. https image URLs are passed through.

Nothing creates posts on its own. The bundled `bighelp-feed-and-ideas` skill tells
agents to publish only what the user asked for, and to set up a scheduled job only
when the user wants something recurring.

## Recording (hooks)

- **Activity:** one row per completed turn that used at least one tool, with the
  user's request (first sentence), the reply's first sentence, the dominant tool
  category and the outcome. Subagent turns and plain chat are not recorded.
- **Approvals history:** `post_approval_response` decisions: Hermes' redacted
  command, its description and the choice.

## Native routes (`native-agent-board-v1`)

All take `agentId` and follow the native context/ETag/request-ID contract.

| Route | Body | Returns |
|---|---|---|
| `board/list` | `kinds`, `limit`, `includeDismissed` | `items` |
| `board/update` | `itemId`, `liked`, `dismissed`, `status` (goals) | `item` |
| `board/media` | `itemId`, `index` | `mimeType`, base64 `data` |
| `board/activity` | `limit` | `activity` with Hermes' session `title` |
| `board/approvals` | `limit` | `approvals` with `sessionTitle` |
