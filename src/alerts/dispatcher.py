"""Real-time alert dispatch routing to Telegram and Discord."""

import asyncio
import logging
from typing import Optional

import aiohttp

from ..config import AppConfig
from ..models import EnrichedDetection

logger = logging.getLogger(__name__)


class AlertDispatcher:
    """Dispatches high-confidence phishing alerts to configured chat webhooks."""

    def __init__(self, config: Optional[AppConfig] = None):
        self.config = config or AppConfig()

    async def dispatch(self, detection: EnrichedDetection) -> None:
        """
        Send detection alerts to all enabled destinations concurrently.
        """
        if not self.config.enable_alerts:
            logger.debug("Alerts are disabled in configuration.")
            return

        tasks = []
        if self.config.telegram_bot_token and self.config.telegram_chat_id:
            tasks.append(self.send_telegram_alert(detection))

        if self.config.discord_webhook_url:
            tasks.append(self.send_discord_alert(detection))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        else:
            logger.info(
                "🚨 [ALERT SIMULATION] Flagged Phishing Domain: %s (Brand: %s, Score: %d)",
                detection.domain,
                ", ".join(detection.matched_brands),
                detection.risk_score,
            )

    async def send_telegram_alert(self, d: EnrichedDetection) -> bool:
        """Send formatted HTML/Markdown alert to Telegram."""
        url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage"
        brands = ", ".join(d.matched_brands) or "Unknown"
        keywords = ", ".join(d.matched_keywords) or "None"
        ips = ", ".join(d.dns_records.a) if d.dns_records and d.dns_records.a else "Unresolved"
        ns = ", ".join(d.dns_records.ns) if d.dns_records and d.dns_records.ns else "None"
        screenshot = d.urlscan.screenshot_url if d.urlscan and d.urlscan.screenshot_url else "N/A"

        text = (
            f"🚨 <b>PHISHING DOMAIN DETECTED</b>\n\n"
            f"<b>Domain:</b> <code>{d.domain}</code>\n"
            f"<b>Target Brand:</b> {brands}\n"
            f"<b>Risk Score:</b> {d.risk_score} / 100\n"
            f"<b>Keywords:</b> {keywords}\n"
            f"<b>Resolved IPs:</b> {ips}\n"
            f"<b>Nameservers:</b> {ns}\n"
            f"<b>Evidence / Screenshot:</b> {screenshot}\n"
            f"<b>Detected At:</b> {d.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )

        payload = {
            "chat_id": self.config.telegram_chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": False,
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, json=payload, timeout=aiohttp.ClientTimeout(total=5.0)
                ) as resp:
                    if resp.status == 200:
                        logger.info("Telegram alert sent for %s", d.domain)
                        return True
                    err = await resp.text()
                    logger.warning("Telegram alert failed (%d): %s", resp.status, err)
                    return False
        except Exception as exc:
            logger.warning("Error dispatching Telegram alert for %s: %s", d.domain, exc)
            return False

    async def send_discord_alert(self, d: EnrichedDetection) -> bool:
        """Send rich embed alert to Discord webhook."""
        color = 0xDC2626 if d.risk_score >= 80 else 0xF59E0B  # Red vs Amber
        brands = ", ".join(d.matched_brands) or "Unknown"
        keywords = ", ".join(d.matched_keywords) or "None"
        ips = ", ".join(d.dns_records.a) if d.dns_records and d.dns_records.a else "Unresolved"
        ns = ", ".join(d.dns_records.ns) if d.dns_records and d.dns_records.ns else "None"

        embed = {
            "title": "🚨 Indian Bank Phishing Domain Detected",
            "description": f"A new high-risk domain targeting **{brands}** has been discovered in CT logs.",
            "color": color,
            "fields": [
                {"name": "Domain", "value": f"`{d.domain}`", "inline": True},
                {"name": "Risk Score", "value": f"**{d.risk_score} / 100**", "inline": True},
                {"name": "Target Brands", "value": brands, "inline": True},
                {"name": "Triggered Keywords", "value": keywords, "inline": False},
                {"name": "Resolved IPs", "value": ips, "inline": True},
                {"name": "Nameservers", "value": ns, "inline": True},
            ],
            "footer": {
                "text": f"Detected: {d.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')} | CT Monitor"
            },
        }

        if d.urlscan and d.urlscan.screenshot_url:
            embed["image"] = {"url": d.urlscan.screenshot_url}

        payload = {
            "username": "Phishing Domain Sentinel",
            "embeds": [embed],
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.config.discord_webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=5.0),
                ) as resp:
                    if resp.status in (200, 204):
                        logger.info("Discord webhook alert sent for %s", d.domain)
                        return True
                    err = await resp.text()
                    logger.warning("Discord alert failed (%d): %s", resp.status, err)
                    return False
        except Exception as exc:
            logger.warning("Error dispatching Discord alert for %s: %s", d.domain, exc)
            return False
