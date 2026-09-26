---
name: bighelp-feed-and-ideas
description: Use when the user wants regular updates, briefings, news, ideas or goal tracking surfaced in the bighelp app's Feed, Ideas or Goals.
---

# bighelp Feed, Ideas and Goals

The bighelp app shows three boards next to the chat. You write to them with the
`bighelp_board` tool:

| Board | Action | What it is |
|---|---|---|
| **Feed** | `post` | Briefings and updates the user asked for: news they follow, a morning brief, a delivery status, a finished report. |
| **Ideas** | `idea` | Concrete things you offer to do for the user, based on what you know. Each one should be doable if they say yes. |
| **Goals** | `goal`, `update_goal` | `section: tracking` for things you keep an eye on (a package, a booking, an inbox watch); `section: goal` for the user's own goals (sleep, savings). Keep the one-line `note` current. |

## Consent comes first

- **Only publish what the user asked for.** Never create a schedule, a recurring
  job or a stream of posts on your own initiative. Scheduled runs spend the
  user's model budget.
- When the user asks for something recurring ("send me AI news every evening",
  "keep an eye on my package"), set it up once, then tell them in one sentence
  what will run and when, and how to stop it.
- A one-off request ("post that summary to my feed") needs no schedule.

## Setting up a recurring update

1. Pin down the topic, the time and how often, from what the user said. Ask one
   short question only if the time or topic is truly unclear.
2. Create a scheduled job with Hermes' scheduling tool. Write its prompt so the
   future run knows exactly what to do, for example:
   > Find the three most important AI news stories from the last 24 hours. For each,
   > call `bighelp_board` with `action: post`, a short title, a two-to-four sentence
   > `body` in plain language, one fitting emoji `icon`, up to two `images` (https
   > URLs from the article or files you downloaded), the article in `links`, and
   > `source: "Evening AI news"`. Do not post duplicates of items already in the feed
   > (check with `action: list`, `kind: feed`).
3. Name the job after what the user will recognise ("Evening AI news").
4. If you give the job its own `enabled_toolsets`, include `loopdy` so the run can
   call `bighelp_board`.

## Writing good items

- **Title:** under 80 characters, specific ("Meta unveils Muse Charm, an AI
  keychain for December"), no clickbait.
- **Body:** the useful part first, in plain words. Markdown links are fine.
- **Icon:** one emoji that matches the item (🗝️, 🧪, 🌙, 📦).
- **Ideas:** write them as offers ("I can audit which apps can read your Google
  account"), with the reason you thought of it. Group related ideas with a short
  `section` such as Health, Shopping or Home. Reuse the same `id` to refresh an
  idea instead of adding a copy.
- **Goals:** create each once with a stable `id` (for example
  `package-hollywood-feed`), then `update_goal` with a fresh `note` whenever it
  changes. Mark `status: done` when it is finished.

## When the user replies from the app

A **Discuss** tap opens a chat that quotes the post or idea. Treat it as the user
wanting to talk about that item, or to go ahead with the idea.
