#!/usr/bin/env python3
"""DailyCTI Demo -- Send the composed newsletter via SMTP to all subscribers."""

import csv
import os
import smtplib
import sys
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from dotenv import load_dotenv

DEMO_DIR = Path(__file__).parent
HTML_FILE = DEMO_DIR / "newsletter_output.html"
TXT_FILE = DEMO_DIR / "newsletter_output.txt"
SUBSCRIBERS_FILE = DEMO_DIR / "subscribers.csv"

# Load .env from demo directory, then project root
load_dotenv(DEMO_DIR / ".env")
load_dotenv(DEMO_DIR.parent / ".env")


def get_smtp_config() -> dict:
    """Load SMTP config from environment variables."""
    config = {
        "SMTP_HOST": os.getenv("SMTP_HOST", "smtp.gmail.com"),
        "SMTP_PORT": int(os.getenv("SMTP_PORT", "587")),
        "SMTP_USERNAME": os.getenv("SMTP_USERNAME", ""),
        "SMTP_PASSWORD": os.getenv("SMTP_PASSWORD", ""),
        "SMTP_SENDER_EMAIL": os.getenv("SMTP_SENDER_EMAIL", ""),
    }

    missing = [k for k in ("SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_SENDER_EMAIL")
               if not config[k]]
    if missing:
        print(f"ERROR: Missing environment variables: {', '.join(missing)}")
        print("  cp demo/.env.example demo/.env && nano demo/.env")
        sys.exit(1)

    return config


def load_subscribers() -> list[dict]:
    """Load subscriber list from CSV file."""
    if not SUBSCRIBERS_FILE.exists():
        print(f"ERROR: {SUBSCRIBERS_FILE} not found.")
        print("  cp demo/subscribers.csv.example demo/subscribers.csv")
        print("  nano demo/subscribers.csv")
        sys.exit(1)

    subscribers = []
    with open(SUBSCRIBERS_FILE, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            email = row.get("email", "").strip()
            if email and not email.startswith("#"):
                subscribers.append({
                    "email": email,
                    "tier": row.get("tier", "technical").strip(),
                    "name": row.get("name", "").strip(),
                })

    if not subscribers:
        print("ERROR: No subscribers found in subscribers.csv")
        sys.exit(1)

    return subscribers


def build_email(config: dict, recipient: dict, html_content: str, txt_content: str) -> MIMEMultipart:
    """Build a MIME multipart email for one subscriber."""
    date_str = datetime.now(timezone.utc).strftime("%B %d, %Y")

    msg = MIMEMultipart("alternative")
    msg["From"] = f"DailyCTI CTI Brief <{config['SMTP_SENDER_EMAIL']}>"
    msg["To"] = recipient["email"]
    msg["Subject"] = f"DailyCTI Daily CTI Brief -- {date_str}"
    msg["Reply-To"] = config["SMTP_SENDER_EMAIL"]
    msg["List-Unsubscribe"] = f"<mailto:{config['SMTP_SENDER_EMAIL']}?subject=unsubscribe>"
    msg["X-Mailer"] = "DailyCTI/0.1.0"

    msg.attach(MIMEText(txt_content, "plain", "utf-8"))
    msg.attach(MIMEText(html_content, "html", "utf-8"))

    return msg


def send_to_all(config: dict, subscribers: list[dict], html_content: str, txt_content: str):
    """Connect once, send to all subscribers."""
    host = config["SMTP_HOST"]
    port = config["SMTP_PORT"]

    print(f"Connecting to {host}:{port}...")

    with smtplib.SMTP(host, port, timeout=30) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        print("TLS established.")

        server.login(config["SMTP_USERNAME"], config["SMTP_PASSWORD"])
        print("Authenticated.")
        print()

        for sub in subscribers:
            msg = build_email(config, sub, html_content, txt_content)
            server.sendmail(
                config["SMTP_SENDER_EMAIL"],
                sub["email"],
                msg.as_string(),
            )
            name = f" ({sub['name']})" if sub["name"] else ""
            print(f"  Sent to {sub['email']}{name} [{sub['tier']}]")

    print(f"\nDelivered to {len(subscribers)} subscriber(s).")


def main():
    print("=" * 60)
    print("DailyCTI Demo -- Newsletter Sender")
    print("=" * 60)
    print()

    # Check files exist
    if not HTML_FILE.exists():
        print(f"ERROR: {HTML_FILE} not found. Run compose_newsletter.py first.")
        sys.exit(1)
    if not TXT_FILE.exists():
        print(f"ERROR: {TXT_FILE} not found. Run compose_newsletter.py first.")
        sys.exit(1)

    # Load config and subscribers
    config = get_smtp_config()
    subscribers = load_subscribers()

    print(f"From: {config['SMTP_SENDER_EMAIL']}")
    print(f"SMTP: {config['SMTP_HOST']}:{config['SMTP_PORT']}")
    print(f"Subscribers: {len(subscribers)}")
    for sub in subscribers:
        name = f" ({sub['name']})" if sub["name"] else ""
        print(f"  - {sub['email']}{name} [{sub['tier']}]")
    print()

    # Load content
    html_content = HTML_FILE.read_text()
    txt_content = TXT_FILE.read_text()
    print(f"HTML size: {len(html_content):,} bytes")
    print(f"Text size: {len(txt_content):,} bytes")
    print()

    # Send
    send_to_all(config, subscribers, html_content, txt_content)
    print("\nDone!")


if __name__ == "__main__":
    main()
