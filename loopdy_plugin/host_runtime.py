"""Read-only, bounded installed-CLI identity; never gateway-version authority."""

from __future__ import annotations

import asyncio
import re
import time


_VERSION_LINE = re.compile(
    rb"^Hermes Agent v([0-9]+(?:\.[0-9]+){2}(?:[-+][A-Za-z0-9.-]+)?)(?=\s|$)"
)
_MAX_OUTPUT_BYTES = 4096
_PROBE_TIMEOUT_SECONDS = 3
_CACHE_SECONDS = 300


class InstalledHermesVersion:
    """Cache successful and unavailable CLI observations without retaining output."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._expires_at = 0.0
        self._version: str | None = None

    async def get(self) -> str | None:
        async with self._lock:
            if time.monotonic() >= self._expires_at:
                self._version = await self._read()
                self._expires_at = time.monotonic() + _CACHE_SECONDS
            return self._version

    @staticmethod
    async def _read() -> str | None:
        process: asyncio.subprocess.Process | None = None

        async def probe() -> str | None:
            nonlocal process
            process = await asyncio.create_subprocess_exec(
                "hermes", "--version",
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                limit=_MAX_OUTPUT_BYTES + 1,
            )
            assert process.stdout is not None
            try:
                # readexactly distinguishes a complete small response from a
                # short pipe read. Oversized output is rejected, never truncated
                # into apparent evidence, and the child is killed in finally.
                await process.stdout.readexactly(_MAX_OUTPUT_BYTES + 1)
                return None
            except asyncio.IncompleteReadError as end:
                output = end.partial
            if await process.wait() != 0:
                return None
            match = _VERSION_LINE.match(output)
            if match is None or len(match[1]) > 64:
                return None
            return match[1].decode("ascii")

        try:
            return await asyncio.wait_for(probe(), timeout=_PROBE_TIMEOUT_SECONDS)
        except (OSError, asyncio.TimeoutError, ValueError, NotImplementedError):
            return None
        finally:
            if process is not None and process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                # Drain only after termination so pipe backpressure cannot
                # strand the process. None of this output leaves the helper.
                try:
                    await asyncio.wait_for(process.communicate(), timeout=1)
                except (OSError, asyncio.TimeoutError):
                    pass
