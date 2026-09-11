"""Request-owned control replies must not finalize a Link assistant turn."""

from __future__ import annotations

import asyncio
import contextvars
import re
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator


_MAX_CONTROL_REPLY_LENGTH = 512


@dataclass
class _ControlReplyCapture:
    adapter: object
    session_id: str
    task: asyncio.Task | None
    reply: str | None = None
    failed: bool = False

    def collect(self, content: str) -> None:
        # Keep one bounded reply, never a transcript or an unbounded error.
        if (
            self.reply is not None
            or not isinstance(content, str)
            or len(content) > _MAX_CONTROL_REPLY_LENGTH
        ):
            self.failed = True
        else:
            self.reply = content

    def validate(self, command: str | None, args: str) -> None:
        reply = self.reply
        if not self.failed and reply is None:
            # Idle handle_message schedules a normal turn instead of replying
            # inline. Its background task owns delivery, even if it inherited us.
            return
        accepted = False
        if command == "queue" and reply is not None:
            accepted = re.fullmatch(
                r"Queued for the next turn\.(?: \([1-9][0-9]* queued\))?", reply
            ) is not None
        elif command == "steer":
            preview = args[:60] + ("..." if len(args) > 60 else "")
            accepted = reply in {
                f"⏩ Steer queued — arrives after the next tool call: '{preview}'",
                "Agent still starting — /steer queued for the next turn.",
                "No active agent — /steer queued for the next turn.",
            }
        if self.failed or not accepted:
            # Base swallows inline send exceptions. Defer failure until dispatch
            # returns so Link emits its existing correlated, user-safe failure.
            raise RuntimeError("Hermes could not confirm this control request.")


_control_reply: contextvars.ContextVar[_ControlReplyCapture | None] = contextvars.ContextVar(
    "loopdy_control_reply", default=None
)


@contextmanager
def capture_control_replies(
    adapter: object, session_id: str, command: str | None, args: str
) -> Iterator[None]:
    capture = _ControlReplyCapture(adapter, session_id, asyncio.current_task())
    token = _control_reply.set(capture)
    try:
        yield
    finally:
        _control_reply.reset(token)
        # A child may retain the copied context after dispatch. Release the task
        # reference and disable capture there, regardless of success/cancellation.
        capture.task = None
    capture.validate(command, args)


def capture_control_reply(adapter: object, session_id: str, content: str) -> bool:
    capture = _control_reply.get()
    if (
        capture is None
        or capture.adapter is not adapter
        or capture.session_id != session_id
        or capture.task is None
        or capture.task is not asyncio.current_task()
    ):
        return False
    capture.collect(content)
    return True
