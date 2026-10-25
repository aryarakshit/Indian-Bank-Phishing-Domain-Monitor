"""Indian Bank Phishing Domain Monitor — Main Pipeline Orchestrator and CLI."""

import argparse
import asyncio
import logging
import signal
import sys
from datetime import datetime, timezone
from typing import Optional

from .alerts import AlertDispatcher
from .config import AppConfig
from .enrichment import EnrichmentPipeline
from .ingestion import CertStreamClient
from .models import EnrichedDetection, TriageResult
from .reports import DailyReportGenerator
from .storage import DatabaseManager
from .triage import RiskScorer

logger = logging.getLogger("phishing_monitor")


class PhishingMonitor:
    """End-to-end pipeline coordinator connecting ingestion, triage, enrichment, storage, and alerts."""

    def __init__(self, config: Optional[AppConfig] = None):
        self.config = config or AppConfig()
        self.db = DatabaseManager(config=self.config)
        self.scorer = RiskScorer(config=self.config)
        self.enrichment = EnrichmentPipeline(config=self.config)
        self.alerts = AlertDispatcher(config=self.config)
        self.reports = DailyReportGenerator(db_manager=self.db, config=self.config)
        self.certstream = CertStreamClient(config=self.config)
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=10_000)
        self._running = False

    async def process_domain(self, domain: str) -> Optional[EnrichedDetection]:
        """
        Execute full lifecycle for an individual domain:
        Triage -> Heuristic Risk Score -> Enrichment -> Persistence -> Alert.
        """
        # Step 1 & 2: Triage & Heuristics
        triage: TriageResult = self.scorer.evaluate(domain)

        if triage.is_whitelisted:
            logger.debug("Whitelisted domain: %s (Ignored)", domain)
            return None

        if not triage.threshold_met:
            logger.debug(
                "Domain below risk threshold: %s (Score: %d, Threshold: %d)",
                domain,
                triage.risk_score,
                self.config.risk_threshold,
            )
            return None

        logger.warning(
            "🚨 HIGH RISK DETECTED: %s [Score: %d] [Brands: %s] [Keywords: %s]",
            domain,
            triage.risk_score,
            ", ".join(triage.matched_brands) or "None",
            ", ".join(triage.matched_keywords) or "None",
        )

        # Step 3: Forensic Enrichment (DNS + sandbox)
        enriched = await self.enrichment.enrich(triage)

        # Step 4: Persistence in SQLite WAL
        det_id = self.db.save_detection(enriched)
        enriched.id = det_id

        # Step 5: Real-Time Alerts
        await self.alerts.dispatch(enriched)

        return enriched

    async def _worker(self) -> None:
        """Asynchronous worker pulling domains from ingestion buffer."""
        while self._running:
            try:
                domain = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                try:
                    await self.process_domain(domain)
                except Exception as exc:
                    logger.error("Error processing domain '%s': %s", domain, exc)
                finally:
                    self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    async def run_stream(self, num_workers: int = 5, max_events: Optional[int] = None) -> None:
        """
        Run continuous real-time monitor ingesting from CertStream.
        """
        self._running = True
        logger.info(
            "Starting Indian Bank Phishing Domain Monitor [Threshold: >= %d]",
            self.config.risk_threshold,
        )

        workers = [asyncio.create_task(self._worker()) for _ in range(num_workers)]
        event_count = 0

        try:
            async for domain in self.certstream.stream_domains():
                if not self._running:
                    break

                try:
                    self._queue.put_nowait(domain)
                except asyncio.QueueFull:
                    logger.warning("Domain queue buffer full; dropping frame to avoid lag.")

                event_count += 1
                if event_count % 1000 == 0:
                    logger.info("Processed %d SSL certificate events...", event_count)

                if max_events and event_count >= max_events:
                    logger.info("Reached maximum event limit (%d). Exiting stream.", max_events)
                    break

        except asyncio.CancelledError:
            logger.info("Stream cancelled by user.")
        finally:
            self._running = False
            self.certstream.stop()
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            logger.info("Monitor shutdown complete.")


def parse_arguments() -> argparse.Namespace:
    """Configure and parse CLI options."""
    parser = argparse.ArgumentParser(
        description="Indian Bank Phishing Domain Monitor — Real-time Certificate Transparency detector.",
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Run real-time CertStream WebSocket monitor.",
    )
    parser.add_argument(
        "--domain",
        type=str,
        help="Analyze a single domain name for phishing risk and forensics.",
    )
    parser.add_argument(
        "--file",
        type=str,
        help="Analyze a batch of domains from a text file (one domain per line).",
    )
    parser.add_argument(
        "--daily-report",
        nargs="?",
        const="yesterday",
        help="Generate daily Markdown audit report. Optional date in YYYY-MM-DD format.",
    )
    parser.add_argument(
        "--recent",
        type=int,
        metavar="N",
        help="Display the most recent N flagged detections.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=60,
        help="Custom risk threshold gate (default: 60).",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO).",
    )
    return parser.parse_args()


async def async_main() -> None:
    """Async CLI entry point."""
    args = parse_arguments()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    config = AppConfig(risk_threshold=args.threshold)
    monitor = PhishingMonitor(config=config)

    # Mode 1: Single domain check
    if args.domain:
        print(f"\n[+] Analyzing domain: {args.domain}")
        result = await monitor.process_domain(args.domain)
        if result:
            print("\n" + "=" * 60)
            print(f"🚨 PHISHING DETECTED: {result.domain}")
            print(f"Risk Score:    {result.risk_score} / 100")
            print(f"Target Brands: {', '.join(result.matched_brands) or 'None'}")
            print(f"Keywords:      {', '.join(result.matched_keywords) or 'None'}")
            if result.dns_records and result.dns_records.a:
                print(f"Resolved IPs:  {', '.join(result.dns_records.a)}")
            if result.dns_records and result.dns_records.ns:
                print(f"Nameservers:   {', '.join(result.dns_records.ns)}")
            print("Reasons:")
            for r in result.reasons:
                print(f"  - {r}")
            print("=" * 60 + "\n")
        else:
            triage = monitor.scorer.evaluate(args.domain)
            print("\n" + "-" * 60)
            if triage.is_whitelisted:
                print(f"✅ LEGITIMATE: {args.domain} is an official whitelisted banking domain.")
            else:
                print(
                    f"ℹ️ BENIGN / LOW RISK: Score is {triage.risk_score} (Threshold is {config.risk_threshold})."
                )
            print("-" * 60 + "\n")
        return

    # Mode 2: Batch file scan
    if args.file:
        from pathlib import Path

        file_path = Path(args.file)
        if not file_path.exists():
            print(f"[-] File not found: {args.file}")
            sys.exit(1)

        domains = [
            line.strip()
            for line in file_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        print(f"[+] Loaded {len(domains)} domains from {args.file}...")
        flagged_count = 0
        for d in domains:
            res = await monitor.process_domain(d)
            if res:
                flagged_count += 1
                print(
                    f"  [FLAGGED] {res.domain} (Score: {res.risk_score}, Brands: {', '.join(res.matched_brands)})"
                )
        print(f"\n[+] Batch complete. Flagged {flagged_count} of {len(domains)} domains.\n")
        return

    # Mode 3: Recent detections
    if args.recent is not None:
        count = args.recent if args.recent > 0 else 10
        records = monitor.db.get_recent_detections(limit=count, min_score=config.risk_threshold)
        print(
            f"\n[+] Displaying {len(records)} recent detections (Score >= {config.risk_threshold}):\n"
        )
        print(f"{'First Seen (UTC)':<20} | {'Score':<5} | {'Brand':<12} | {'Domain'}")
        print("-" * 75)
        for r in records:
            time_str = r.first_seen.strftime("%Y-%m-%d %H:%M:%S")
            brand = ", ".join(r.matched_brands) or "-"
            print(f"{time_str:<20} | {r.risk_score:<5} | {brand:<12} | {r.domain}")
        print("-" * 75 + "\n")
        return

    # Mode 4: Daily Report
    if args.daily_report is not None:
        target_date = None
        if args.daily_report != "yesterday":
            try:
                target_date = datetime.strptime(args.daily_report, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                )
            except ValueError:
                print(f"[-] Invalid date format: {args.daily_report}. Use YYYY-MM-DD.")
                sys.exit(1)

        report_file = monitor.reports.generate_report(target_date=target_date)
        print(f"[+] Daily report successfully generated: {report_file}")
        return

    # Mode 5: Stream monitor (default if --stream provided or fallback)
    if args.stream:
        loop = asyncio.get_running_loop()

        def stop_handler():
            logger.info("Termination signal received. Stopping stream...")
            monitor._running = False
            monitor.certstream.stop()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop_handler)
            except (NotImplementedError, RuntimeError):
                pass  # add_signal_handler is not fully supported on some Windows event loops

        await monitor.run_stream()
        return

    # If no flags passed, print help
    print("\nIndian Bank Phishing Domain Monitor — CLI")
    print("Use '--help' to see all options.")
    print("Quick examples:")
    print("  python -m src.main --domain sbi-kyc-update-pan.top")
    print("  python -m src.main --stream")
    print("  python -m src.main --recent 10")
    print("  python -m src.main --daily-report\n")


def main() -> None:
    """Synchronous entry point."""
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if sys.stderr and hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\n[+] Exited cleanly.")


if __name__ == "__main__":
    main()
