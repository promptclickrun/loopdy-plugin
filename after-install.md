# Loopdy installed

1. Create or sign in to the passkey-backed Loopdy account in the app.

2. Start proof-of-possession pairing on the Hermes host:

   ```bash
   hermes loopdy link pair
   ```

   In Loopdy, open **Settings → Loopdy Link → Pair a Device**, then scan the QR code or enter the short-lived six-character code.

3. Pairing stores the host credentials through Hermes' configuration writer and asks the official Hermes lifecycle command to activate the gateway automatically. Once pairing completes, the same encrypted Link connection supplies chats, agents, sessions, scheduled tasks, per-agent defaults, approvals, events, and attachments. There is no gateway URL or token to enter in the app.

4. Pairing automatically reconciles APNs registration for the current iPhone or iPad and pins Loopdy Link's account-scoped wake-relay keys. The wake channel does not install or share a host relay credential. A self-hoster can separately configure the optional notification relay or choose **Direct / Self-hosted** after supplying its own APNs credentials.

5. If needed, verify Link health. If a separate notification provider has been configured, verify it and send a provider test too:

   ```bash
   hermes loopdy link status
   hermes loopdy status
   hermes loopdy test --target all
   ```

Loopdy Link and the notification relay are separate services and protocols. Chat frames traverse Loopdy Link only as account-encrypted ciphertext. Notification delivery uses the configured encrypted relay enrollment; users with their own Apple developer credentials can configure direct APNs as described in `README.md`.

Loopdy's native Generative UI renderers are direct model tools. Agents should call a visible `loopdy_render_*` tool directly. When Hermes has progressively disclosed a renderer and it is absent, use the official tool bridge to search for, describe, and invoke that exact renderer. Inline cards stay on the active conversation response path; do not send a notification merely to answer the current chat. Proactive and scheduled Agent Inbox/Home cards must explicitly target `loopdy` and use the exact validated renderer envelope as the complete delivered content because Hermes does not auto-forward an earlier renderer result to a later channel send. Never script or reconstruct the envelope. Detailed examples are available from the registered read-only skill with `skill_view("loopdy:generative-ui")`.

To route Hermes approvals to Loopdy, explicitly select the transport in `config.yaml`:

```yaml
security:
  approval:
    transport: loopdy
    transport_fallback: deny
```
