# Loopdy installed

Connect Loopdy to your authenticated Hermes host address using Tailscale or your local network, then sign in using the host's native provider or access token. Hermes owns chats, sessions, tools and approvals over native REST and `/api/ws`.

No Cloudflare account, pairing code, public URL, cloud queue or Link chat worker is required. Old paired Direct listener settings are retained only for compatibility and do not activate a chat listener.

Notifications and Live Activities are optional. Sign in to the notification account and explicitly enable delivery for your host in the app when wanted. Delivery setup does not control chat connectivity or session state.

Restart the Hermes gateway and dashboard through their normal lifecycle controls to load updated plugin code. The app negotiates supported native capabilities after reconnecting. Hermes 0.21.1 and 0.21.2 are supported.

Loopdy's native Generative UI renderers are direct model tools. Agents should call a visible `loopdy_render_*` tool directly. When Hermes has progressively disclosed a renderer and it is absent, use the official tool bridge to search for, describe, and invoke that exact renderer. Inline cards stay on the active conversation response path; do not send a notification merely to answer the current chat. Proactive and scheduled Agent Inbox/Home cards must explicitly target `loopdy` and use the exact validated renderer envelope as the complete delivered content because Hermes does not auto-forward an earlier renderer result to a later channel send. Never script or reconstruct the envelope. Detailed examples are available from the registered read-only skill with `skill_view("loopdy:generative-ui")`.

Native chat approvals stay with the Hermes native session. Do not change the global approval transport to enable chat.
