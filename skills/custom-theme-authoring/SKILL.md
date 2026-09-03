---
name: custom-theme-authoring
description: Create importable Loopdy custom-theme JSON files from a user's visual direction.
---

# Loopdy Custom Theme Authoring

Use this skill when a user asks you to design, generate, revise, or package a custom Loopdy theme.

## Deliverable

Create a UTF-8 JSON file that Loopdy can import from **Settings > Themes > Import**. Deliver the file as an attachment in the active Loopdy chat. Do not paste JSON as the only deliverable when file delivery is available.

The file must use this envelope:

```json
{
  "schemaVersion": 1,
  "themes": [
    {
      "id": "A NEW LOWERCASE-OR-UPPERCASE UUID",
      "name": "Theme name, 1-40 characters",
      "font": "system",
      "accentHex": "3366CC",
      "light": {
        "backgroundHex": "FFFFFF",
        "primaryTextHex": "111111",
        "secondaryTextHex": "333333",
        "tertiaryTextHex": "555555"
      },
      "dark": {
        "backgroundHex": "101010",
        "primaryTextHex": "FFFFFF",
        "secondaryTextHex": "E0E0E0",
        "tertiaryTextHex": "B0B0B0"
      }
    }
  ]
}
```

## Rules

- Generate a fresh UUID for each new theme. Preserve the UUID when revising an exported theme.
- Allowed `font` values: `system`, `rounded`, `serif`, `monospaced`, `notoSans`.
- Every color is exactly six hexadecimal digits, without `#` or alpha.
- Keep primary, secondary, and tertiary text readable against that mode's background. Loopdy enforces at least a 4.5:1 contrast ratio for every text color.
- Keep `schemaVersion` at `1`.
- A catalog can contain up to 24 unique themes.
- Do not include `logo`, `lightLogo`, or `darkLogo` metadata. Logo image files remain device-local and are selected separately in the theme editor for light and dark mode.
- Do not add unknown keys, comments, trailing commas, executable content, URLs, or secrets.
- Validate JSON syntax and contrast before delivery.

## Workflow

1. Translate the user's visual direction into one accent and two four-color palettes.
2. Calculate WCAG contrast for every text/background pair and adjust any result below 4.5:1.
3. Write the exact import envelope to a `.json` file.
4. Parse the completed file once to verify valid JSON, unique UUIDs, allowed fonts, six-digit colors, and the 24-theme limit.
5. Deliver the JSON file in Loopdy and tell the user to import it from **Settings > Themes > Import**.
