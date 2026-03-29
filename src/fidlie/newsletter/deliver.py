"""Newsletter delivery -- MIME construction, SMTP sending, subscriber management.

Provides utilities to build MIME multipart/alternative email messages and
deliver them via SMTP with TLS support and retry logic.
"""

from __future__ import annotations

import email.charset
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any


# Use quoted-printable encoding so content is readable in msg.as_string()
_QP_CHARSET = email.charset.Charset("utf-8")
_QP_CHARSET.body_encoding = email.charset.QP


# ---------------------------------------------------------------------------
# MIME message construction
# ---------------------------------------------------------------------------

def build_mime_message(
    html: str,
    plaintext: str,
    subject: str,
    config: dict,
    recipients: list[str],
) -> MIMEMultipart:
    """Build a MIME multipart/alternative message with HTML + plaintext parts.

    Raises ValueError if recipients is empty.
    """
    if not recipients:
        raise ValueError("recipients list must not be empty")

    nl_cfg = config.get("newsletter", {})
    delivery_cfg = config.get("delivery", {})

    from_name = nl_cfg.get("from_name", "DailyCTI Intelligence")
    from_email = nl_cfg.get("from_email", "noreply@example.com")
    reply_to = nl_cfg.get("reply_to")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = ", ".join(recipients)

    if reply_to:
        msg["Reply-To"] = reply_to

    # List-Unsubscribe header (RFC 8058)
    if delivery_cfg.get("include_list_unsubscribe", False):
        website_url = nl_cfg.get("website_url", "https://example.com")
        msg["List-Unsubscribe"] = f"<{website_url}/unsubscribe>"

    msg["X-Mailer"] = "DailyCTI Newsletter Delivery"

    # Attach parts: plaintext first, then HTML (per RFC 2046 -- last is preferred)
    text_part = MIMEText(plaintext, "plain")
    text_part.set_charset(_QP_CHARSET)
    html_part = MIMEText(html, "html")
    html_part.set_charset(_QP_CHARSET)
    msg.attach(text_part)
    msg.attach(html_part)

    return msg


# ---------------------------------------------------------------------------
# SMTP delivery
# ---------------------------------------------------------------------------

async def send_newsletter(
    html: str,
    plaintext: str,
    config: dict,
    recipients: list[str],
    subject: str | None = None,
) -> None:
    """Build and send a newsletter email.

    Creates a NewsletterDelivery instance and delegates to it.
    In tests, patch NewsletterDelivery._smtp_send at the class level.
    """
    if subject is None:
        nl_name = config.get("newsletter", {}).get("name", "DailyCTI Brief")
        subject = nl_name

    delivery = NewsletterDelivery(config)
    await delivery.send(html=html, plaintext=plaintext, recipients=recipients, subject=subject)


# ---------------------------------------------------------------------------
# NewsletterDelivery class
# ---------------------------------------------------------------------------

class NewsletterDelivery:
    """Wraps MIME construction and SMTP delivery with retry logic."""

    def __init__(self, config: dict):
        self.config = config
        delivery_cfg = config.get("delivery", {})
        smtp_cfg = delivery_cfg.get("smtp", {})
        self.smtp_host: str = smtp_cfg.get("host", "localhost")
        self.smtp_port: int = smtp_cfg.get("port", 587)
        self.use_tls: bool = smtp_cfg.get("use_tls", True)
        self.smtp_username: str = smtp_cfg.get("username", "")
        self.smtp_password: str = smtp_cfg.get("password", "")
        self.max_retries: int = delivery_cfg.get("max_retries", 3)
        self.retry_delay: int = delivery_cfg.get("retry_delay_seconds", 60)

    async def send(
        self,
        html: str,
        plaintext: str,
        recipients: list[str],
        subject: str | None = None,
    ) -> None:
        """Build the MIME message and send it, retrying on transient failures."""
        if subject is None:
            nl_name = self.config.get("newsletter", {}).get("name", "DailyCTI Brief")
            subject = nl_name

        msg = build_mime_message(
            html=html,
            plaintext=plaintext,
            subject=subject,
            config=self.config,
            recipients=recipients,
        )

        last_exc: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                await self._smtp_send(msg, recipients)
                return
            except (ConnectionResetError, ConnectionRefusedError, TimeoutError, OSError) as exc:
                last_exc = exc
                if attempt == self.max_retries:
                    raise
            except Exception:
                raise

        if last_exc is not None:
            raise last_exc

    async def _smtp_send(self, msg: MIMEMultipart, recipients: list[str]) -> None:
        """Perform the actual SMTP send (can be mocked in tests)."""
        nl_cfg = self.config.get("newsletter", {})
        from_email = nl_cfg.get("from_email", "noreply@example.com")

        if self.use_tls:
            server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30)
            server.ehlo()
            server.starttls()
            server.ehlo()
        else:
            server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30)

        try:
            if self.smtp_username:
                server.login(self.smtp_username, self.smtp_password)
            server.sendmail(from_email, recipients, msg.as_string())
        finally:
            server.quit()
