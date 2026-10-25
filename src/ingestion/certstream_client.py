"""CertStream WebSocket client for live Certificate Transparency log ingestion."""

import asyncio
import json
import logging
from typing import Any, AsyncIterator, Callable, Optional

import websockets

from ..config import AppConfig
from .sanitizer import extract_domains_from_cert

logger = logging.getLogger(__name__)


class FeedStalledError(Exception):
    """The WebSocket is open but no certificates have arrived within the idle timeout."""


class CertStreamClient:
    """Asynchronous WebSocket client connecting to CertStream log stream."""

    def __init__(
        self,
        config: Optional[AppConfig] = None,
        connect: Callable[..., Any] = websockets.connect,
    ):
        self.config = config or AppConfig()
        self.urls = [self.config.certstream_url, *self.config.certstream_fallback_urls]
        self.url = self.urls[0]
        self.idle_timeout = self.config.certstream_idle_timeout_seconds
        self._connect = connect
        self._running = False

    def stop(self) -> None:
        """Signal client to cease streaming."""
        self._running = False

    async def _next_message(self, ws: Any, last_cert_at: float) -> str:
        """Wait for the next frame, raising FeedStalledError once the idle budget runs out."""
        loop = asyncio.get_running_loop()
        remaining = self.idle_timeout - (loop.time() - last_cert_at)
        try:
            if remaining <= 0:
                raise asyncio.TimeoutError
            return await asyncio.wait_for(ws.recv(), timeout=remaining)
        except asyncio.TimeoutError:
            raise FeedStalledError(
                f"No certificates from {self.url} for {self.idle_timeout:.0f}s"
            ) from None

    async def stream_domains(self) -> AsyncIterator[str]:
        """
        Continuously stream sanitized domain names from CertStream.
        Reconnection with exponential backoff is handled automatically, and a feed that
        stays silent past the idle timeout is abandoned for the next configured URL.
        """
        self._running = True
        backoff = 1.0
        max_backoff = 30.0
        feed_index = 0
        loop = asyncio.get_running_loop()

        while self._running:
            self.url = self.urls[feed_index % len(self.urls)]
            try:
                logger.info("Connecting to CertStream WebSocket: %s", self.url)
                async with self._connect(
                    self.url,
                    ping_interval=20,
                    ping_timeout=20,
                    max_size=10_000_000,
                ) as ws:
                    logger.info("Connected successfully to CertStream.")
                    # Heartbeats prove the socket is alive, not that certificates flow,
                    # so only certificate frames reset the idle clock.
                    last_cert_at = loop.time()

                    while self._running:
                        try:
                            raw_message = await self._next_message(ws, last_cert_at)
                            message = json.loads(raw_message)

                            # Ignore heartbeat / internal ping frames
                            if message.get("message_type") == "heartbeat":
                                continue

                            last_cert_at = loop.time()
                            backoff = 1.0  # Reset backoff once real data flows
                            domains = extract_domains_from_cert(message)
                            for domain in domains:
                                yield domain

                        except json.JSONDecodeError:
                            logger.warning("Skipping malformed JSON frame.")
                            continue

            except FeedStalledError as exc:
                if not self._running:
                    break
                feed_index += 1
                logger.warning(
                    "%s; the feed looks stalled. Switching to %s",
                    exc,
                    self.urls[feed_index % len(self.urls)],
                )
            except (websockets.ConnectionClosed, OSError, asyncio.TimeoutError) as exc:
                if not self._running:
                    break
                feed_index += 1
                logger.warning(
                    "WebSocket disconnected (%s). Retrying in %.1f seconds...", exc, backoff
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2.0, max_backoff)
            except Exception as exc:
                if not self._running:
                    break
                logger.error("Unexpected error in CertStream client: %s", exc, exc_info=True)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2.0, max_backoff)
