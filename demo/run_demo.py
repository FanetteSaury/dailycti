#!/usr/bin/env python3
"""DailyCTI Demo -- One-click pipeline: scrape → compose → send.

Usage:
    1. cp demo/.env.example demo/.env
    2. Edit demo/.env with your SMTP credentials and recipient email
    3. python demo/run_demo.py

Or run individual stages:
    python demo/scrape_feeds.py      # Scrape RSS feeds
    python demo/compose_newsletter.py # Compose HTML newsletter
    python demo/send_newsletter.py    # Send via SMTP
"""

import subprocess
import sys
from pathlib import Path

DEMO_DIR = Path(__file__).parent
SCRIPTS = [
    ("Scraping RSS feeds", "scrape_feeds.py"),
    ("Composing newsletter", "compose_newsletter.py"),
    ("Sending newsletter", "send_newsletter.py"),
]


def main():
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║          DAILYCTI -- Daily CTI Newsletter Demo             ║")
    print("║          Scrape → Compose → Send                        ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    # Check .env exists
    env_file = DEMO_DIR / ".env"
    if not env_file.exists():
        print("ERROR: demo/.env not found!")
        print()
        print("Setup:")
        print("  cp demo/.env.example demo/.env")
        print("  nano demo/.env  # fill in your SMTP credentials")
        print()
        sys.exit(1)

    for i, (description, script) in enumerate(SCRIPTS, 1):
        print(f"\n{'─' * 60}")
        print(f"  Stage {i}/3: {description}")
        print(f"{'─' * 60}\n")

        result = subprocess.run(
            [sys.executable, str(DEMO_DIR / script)],
            cwd=str(DEMO_DIR.parent),
        )

        if result.returncode != 0:
            print(f"\nERROR: {script} failed with exit code {result.returncode}")
            sys.exit(result.returncode)

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  Pipeline complete! Check your inbox.                   ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()


if __name__ == "__main__":
    main()
