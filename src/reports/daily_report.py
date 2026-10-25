"""Daily Markdown audit report generation."""

import logging
from collections import Counter
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from ..config import AppConfig
from ..models import EnrichedDetection
from ..storage import DatabaseManager

logger = logging.getLogger(__name__)


class DailyReportGenerator:
    """Compiles 24-hour phishing intelligence reports in Markdown."""

    def __init__(self, db_manager: DatabaseManager, config: Optional[AppConfig] = None):
        self.db = db_manager
        self.config = config or AppConfig()
        self.reports_dir = self.config.reports_dir
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, target_date: Optional[datetime] = None) -> Path:
        """
        Build and write a Markdown audit report for a specific 24h date period.

        Args:
            target_date: Datetime object representing the day to summarize.
                         Defaults to yesterday if not specified.

        Returns:
            Path to the generated Markdown file.
        """
        now = datetime.now(timezone.utc)
        if target_date is None:
            # Default to the previous 24-hour cycle
            target_date = now - timedelta(days=1)

        date_str = target_date.strftime("%Y-%m-%d")
        start_time = datetime.combine(target_date.date(), time.min).replace(tzinfo=timezone.utc)
        end_time = datetime.combine(target_date.date(), time.max).replace(tzinfo=timezone.utc)

        detections = self.db.get_detections_by_timerange(start_time, end_time)

        report_content = self._render_markdown(date_str, detections)
        report_file = self.reports_dir / f"daily_{date_str}.md"
        report_file.write_text(report_content, encoding="utf-8")

        logger.info(
            "Generated daily phishing report: %s (%d detections)", report_file, len(detections)
        )
        return report_file

    def _render_markdown(self, date_str: str, detections: List[EnrichedDetection]) -> str:
        """Render the Markdown report string."""
        total = len(detections)

        # Aggregate brand statistics
        brand_counter: Counter[str] = Counter()
        for d in detections:
            for b in d.matched_brands:
                brand_counter[b] += 1

        # Aggregate keyword statistics
        keyword_counter: Counter[str] = Counter()
        for d in detections:
            for kw in d.matched_keywords:
                keyword_counter[kw] += 1

        # Aggregate TLD statistics
        tld_counter: Counter[str] = Counter()
        for d in detections:
            if d.suffix:
                tld_counter[d.suffix] += 1

        lines = [
            f"# Indian Bank Phishing Domain Daily Report — {date_str}",
            "",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Total High-Risk Detections:** {total}  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            f"During the 24-hour observation period on `{date_str}`, the real-time Certificate Transparency monitor flagged a total of **{total}** domains exhibiting phishing characteristics targeting Indian banking and financial systems.",
            "",
            "### Targeted Brands Breakdown",
            "",
            "| Brand | Detections Count | Percentage |",
            "|---|---|---|",
        ]

        if brand_counter:
            for brand, count in brand_counter.most_common():
                pct = (count / total * 100) if total > 0 else 0
                lines.append(f"| {brand} | {count} | {pct:.1f}% |")
        else:
            lines.append("| None | 0 | 0.0% |")

        lines.extend(
            [
                "",
                "### Most Frequent Threat Keywords",
                "",
                "| Keyword | Occurrences |",
                "|---|---|",
            ]
        )

        if keyword_counter:
            for kw, count in keyword_counter.most_common(10):
                lines.append(f"| `{kw}` | {count} |")
        else:
            lines.append("| None | 0 |")

        lines.extend(
            [
                "",
                "### Top Phishing TLDs",
                "",
                "| TLD | Count |",
                "|---|---|",
            ]
        )

        if tld_counter:
            for tld, count in tld_counter.most_common(5):
                lines.append(f"| `.{tld}` | {count} |")
        else:
            lines.append("| None | 0 |")

        lines.extend(
            [
                "",
                "---",
                "",
                "## 2. Detailed Threat Detections Register",
                "",
                "| Time (UTC) | Domain | Score | Target Brand | Triggered Keywords | Resolved IP(s) |",
                "|---|---|---|---|---|---|",
            ]
        )

        if detections:
            for d in detections:
                time_str = d.first_seen.strftime("%H:%M:%S")
                brands_str = ", ".join(d.matched_brands) or "-"
                kws_str = ", ".join(d.matched_keywords) or "-"
                ips_str = (
                    ", ".join(d.dns_records.a)
                    if d.dns_records and d.dns_records.a
                    else "Unresolved"
                )
                lines.append(
                    f"| {time_str} | `{d.domain}` | **{d.risk_score}** | {brands_str} | {kws_str} | {ips_str} |"
                )
        else:
            lines.append("| - | *No high-risk domains recorded in this period.* | - | - | - | - |")

        lines.append("")
        return "\n".join(lines)
