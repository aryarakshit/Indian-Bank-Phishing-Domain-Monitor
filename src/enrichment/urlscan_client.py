"""Integration client for urlscan.io sandbox submission and telemetry."""

import asyncio
import logging
from typing import Optional

import aiohttp

from ..config import AppConfig
from ..models import UrlscanResult

logger = logging.getLogger(__name__)


class UrlscanClient:
    """Submits suspect domains to urlscan.io for headless sandboxing and screenshots."""

    def __init__(self, config: Optional[AppConfig] = None):
        self.config = config or AppConfig()
        self.api_key = self.config.urlscan_api_key
        self.enabled = self.config.enable_urlscan and bool(self.api_key)
        self.base_url = "https://urlscan.io/api/v1"

    async def submit(self, domain: str, wait_for_result: bool = False) -> UrlscanResult:
        """
        Submit a domain to urlscan.io.

        Args:
            domain: Target domain to scan.
            wait_for_result: If True, polls for completed screenshot and page title.

        Returns:
            UrlscanResult object with scan telemetry.
        """
        if not self.enabled:
            return UrlscanResult(
                submitted=False,
                error="URLScan disabled or no API key provided.",
            )

        headers = {
            "API-Key": self.api_key,
            "Content-Type": "application/json",
        }
        payload = {
            "url": f"http://{domain}",
            "visibility": "unlisted",
        }

        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.post(
                    f"{self.base_url}/scan/",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10.0),
                ) as resp:
                    if resp.status not in (200, 201):
                        err_text = await resp.text()
                        logger.warning("urlscan.io error HTTP %d: %s", resp.status, err_text)
                        return UrlscanResult(
                            submitted=False,
                            error=f"HTTP {resp.status}: {err_text}",
                        )

                    data = await resp.json()
                    scan_uuid = data.get("uuid")
                    result_url = data.get("result")

                    result = UrlscanResult(
                        submitted=True,
                        scan_id=scan_uuid,
                        result_url=result_url,
                        screenshot_url=f"https://urlscan.io/screenshots/{scan_uuid}.png"
                        if scan_uuid
                        else None,
                    )

                    if wait_for_result and scan_uuid:
                        # Optional polling up to 15 seconds
                        result = await self._poll_result(session, scan_uuid, result)

                    return result

        except asyncio.TimeoutError:
            return UrlscanResult(submitted=False, error="Timeout submitting to urlscan.io")
        except Exception as exc:
            logger.warning("urlscan.io submission error for %s: %s", domain, exc)
            return UrlscanResult(submitted=False, error=str(exc))

    async def _poll_result(
        self, session: aiohttp.ClientSession, scan_uuid: str, current_result: UrlscanResult
    ) -> UrlscanResult:
        """Poll urlscan.io result API up to 3 times."""
        poll_url = f"{self.base_url}/result/{scan_uuid}/"
        for _ in range(3):
            await asyncio.sleep(5.0)
            try:
                async with session.get(poll_url, timeout=aiohttp.ClientTimeout(total=5.0)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        page = data.get("page", {})
                        current_result.page_title = page.get("title")
                        current_result.page_status = page.get("status")
                        return current_result
            except Exception:
                pass
        return current_result
