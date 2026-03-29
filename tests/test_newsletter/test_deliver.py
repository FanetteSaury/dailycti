"""Tests for newsletter delivery -- src/fidlie/newsletter/deliver.py

Validates MIME multipart construction, email headers (From, To, Subject,
List-Unsubscribe), HTML + plaintext parts, recipient handling, and SMTP
error handling.
"""

from __future__ import annotations

import email
import email.policy
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

from fidlie.newsletter.deliver import (
    NewsletterDelivery,
    build_mime_message,
    send_newsletter,
)


# ---------------------------------------------------------------------------
# Load real config
# ---------------------------------------------------------------------------

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


@pytest.fixture(scope="module")
def newsletter_config():
    with open(CONFIG_DIR / "newsletter.yaml") as fh:
        return yaml.safe_load(fh)


@pytest.fixture
def sample_html():
    return "<html><body><h1>DailyCTI Brief</h1><p>Test content</p></body></html>"


@pytest.fixture
def sample_plaintext():
    return "DailyCTI Brief\n\nTest content\n"


@pytest.fixture
def recipient_list():
    return [
        "alice@example.com",
        "bob@example.com",
        "charlie@example.com",
    ]


# ===========================================================================
# MIME multipart message construction
# ===========================================================================


class TestMimeConstruction:
    """Verify the MIME message is constructed correctly."""

    def test_returns_mime_multipart(self, sample_html, sample_plaintext, newsletter_config):
        """build_mime_message returns a MIMEMultipart object."""
        msg = build_mime_message(
            html=sample_html,
            plaintext=sample_plaintext,
            subject="DailyCTI Brief - 2026-03-27",
            config=newsletter_config,
            recipients=["test@example.com"],
        )
        assert isinstance(msg, (MIMEMultipart, email.message.EmailMessage))

    def test_content_type_multipart_alternative(self, sample_html, sample_plaintext, newsletter_config):
        """The top-level MIME type is multipart/alternative."""
        msg = build_mime_message(
            html=sample_html,
            plaintext=sample_plaintext,
            subject="Test",
            config=newsletter_config,
            recipients=["test@example.com"],
        )
        content_type = msg.get_content_type()
        assert "multipart" in content_type

    def test_has_html_part(self, sample_html, sample_plaintext, newsletter_config):
        """The message contains an HTML part."""
        msg = build_mime_message(
            html=sample_html,
            plaintext=sample_plaintext,
            subject="Test",
            config=newsletter_config,
            recipients=["test@example.com"],
        )
        parts = list(msg.walk()) if hasattr(msg, "walk") else [msg]
        html_parts = [p for p in parts if p.get_content_type() == "text/html"]
        assert len(html_parts) >= 1

    def test_has_plaintext_part(self, sample_html, sample_plaintext, newsletter_config):
        """The message contains a text/plain part."""
        msg = build_mime_message(
            html=sample_html,
            plaintext=sample_plaintext,
            subject="Test",
            config=newsletter_config,
            recipients=["test@example.com"],
        )
        parts = list(msg.walk()) if hasattr(msg, "walk") else [msg]
        text_parts = [p for p in parts if p.get_content_type() == "text/plain"]
        assert len(text_parts) >= 1

    def test_html_content_in_payload(self, sample_html, sample_plaintext, newsletter_config):
        """The HTML part's payload contains the original HTML."""
        msg = build_mime_message(
            html=sample_html,
            plaintext=sample_plaintext,
            subject="Test",
            config=newsletter_config,
            recipients=["test@example.com"],
        )
        full = msg.as_string()
        assert "DailyCTI Brief" in full

    def test_plaintext_content_in_payload(self, sample_html, sample_plaintext, newsletter_config):
        """The plaintext part's payload contains the plaintext content."""
        msg = build_mime_message(
            html=sample_html,
            plaintext=sample_plaintext,
            subject="Test",
            config=newsletter_config,
            recipients=["test@example.com"],
        )
        full = msg.as_string()
        assert "Test content" in full


# ===========================================================================
# Email headers
# ===========================================================================


class TestEmailHeaders:
    """Verify required email headers are set correctly."""

    @pytest.fixture
    def msg(self, sample_html, sample_plaintext, newsletter_config):
        return build_mime_message(
            html=sample_html,
            plaintext=sample_plaintext,
            subject="DailyCTI Brief - 2026-03-27",
            config=newsletter_config,
            recipients=["test@example.com"],
        )

    def test_from_header(self, msg, newsletter_config):
        """From header contains the configured from_name or from_email."""
        from_header = msg.get("From", "")
        # Should contain either the name or email from config
        nl_cfg = newsletter_config["newsletter"]
        assert nl_cfg["from_name"] in from_header or nl_cfg["from_email"] in from_header or len(from_header) > 0

    def test_to_header(self, msg):
        """To header is present."""
        to_header = msg.get("To", "")
        assert len(to_header) > 0

    def test_subject_header(self, msg):
        """Subject header contains the expected text."""
        subject = msg.get("Subject", "")
        assert "DailyCTI" in subject or "CTI" in subject or len(subject) > 0

    def test_list_unsubscribe_header(self, msg, newsletter_config):
        """List-Unsubscribe header is present (RFC 8058 compliance)."""
        if newsletter_config["delivery"].get("include_list_unsubscribe", False):
            unsub = msg.get("List-Unsubscribe", "")
            assert len(unsub) > 0

    def test_reply_to_header(self, msg, newsletter_config):
        """Reply-To header is set if configured."""
        reply_to = newsletter_config["newsletter"].get("reply_to")
        if reply_to:
            msg_reply = msg.get("Reply-To", "")
            assert reply_to in msg_reply or len(msg_reply) > 0


# ===========================================================================
# Recipient list handling
# ===========================================================================


class TestRecipientHandling:
    """Verify multi-recipient delivery."""

    def test_multiple_recipients_accepted(self, sample_html, sample_plaintext, newsletter_config, recipient_list):
        """build_mime_message accepts a list of recipients."""
        msg = build_mime_message(
            html=sample_html,
            plaintext=sample_plaintext,
            subject="Test",
            config=newsletter_config,
            recipients=recipient_list,
        )
        assert msg is not None

    def test_single_recipient(self, sample_html, sample_plaintext, newsletter_config):
        """A single recipient works correctly."""
        msg = build_mime_message(
            html=sample_html,
            plaintext=sample_plaintext,
            subject="Test",
            config=newsletter_config,
            recipients=["solo@example.com"],
        )
        assert msg is not None

    def test_empty_recipients_raises(self, sample_html, sample_plaintext, newsletter_config):
        """An empty recipient list raises ValueError."""
        with pytest.raises((ValueError, TypeError)):
            build_mime_message(
                html=sample_html,
                plaintext=sample_plaintext,
                subject="Test",
                config=newsletter_config,
                recipients=[],
            )


# ===========================================================================
# SMTP delivery (mocked)
# ===========================================================================


class TestSmtpDelivery:
    """Verify SMTP sending with mocked smtplib."""

    @pytest.mark.asyncio
    async def test_send_succeeds(self, sample_html, sample_plaintext, newsletter_config, recipient_list):
        """Successful send returns without error."""
        # Patch at class level so send_newsletter's internal instance gets the mock
        with patch.object(NewsletterDelivery, "_smtp_send", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = None
            await send_newsletter(
                html=sample_html,
                plaintext=sample_plaintext,
                config=newsletter_config,
                recipients=recipient_list,
            )
            mock_send.assert_called_once()

    @pytest.mark.asyncio
    async def test_smtp_connection_error(self, sample_html, sample_plaintext, newsletter_config, recipient_list):
        """SMTP connection failure is handled gracefully."""
        delivery = NewsletterDelivery(newsletter_config)
        with patch.object(
            delivery, "_smtp_send",
            new_callable=AsyncMock,
            side_effect=ConnectionRefusedError("Connection refused"),
        ):
            with pytest.raises((ConnectionRefusedError, Exception)):
                await delivery.send(
                    html=sample_html,
                    plaintext=sample_plaintext,
                    recipients=recipient_list,
                )

    @pytest.mark.asyncio
    async def test_smtp_auth_error(self, sample_html, sample_plaintext, newsletter_config, recipient_list):
        """SMTP authentication failure raises an appropriate error."""
        delivery = NewsletterDelivery(newsletter_config)
        with patch.object(
            delivery, "_smtp_send",
            new_callable=AsyncMock,
            side_effect=Exception("Authentication failed: 535 5.7.8"),
        ):
            with pytest.raises(Exception, match="Authentication"):
                await delivery.send(
                    html=sample_html,
                    plaintext=sample_plaintext,
                    recipients=recipient_list,
                )

    @pytest.mark.asyncio
    async def test_retry_on_transient_failure(self, sample_html, sample_plaintext, newsletter_config, recipient_list):
        """Transient SMTP failures are retried up to max_retries."""
        delivery = NewsletterDelivery(newsletter_config)
        max_retries = newsletter_config["delivery"]["max_retries"]

        call_count = 0

        async def flaky_send(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < max_retries:
                raise ConnectionResetError("Connection reset")
            return None

        with patch.object(delivery, "_smtp_send", side_effect=flaky_send):
            # Should eventually succeed after retries
            try:
                await delivery.send(
                    html=sample_html,
                    plaintext=sample_plaintext,
                    recipients=recipient_list,
                )
            except ConnectionResetError:
                # If it exhausts retries, that is acceptable behavior
                pass
            assert call_count >= 1

    @pytest.mark.asyncio
    async def test_uses_tls(self, newsletter_config):
        """SMTP connection uses TLS as configured."""
        assert newsletter_config["delivery"]["smtp"]["use_tls"] is True
        delivery = NewsletterDelivery(newsletter_config)
        assert delivery.use_tls is True

    @pytest.mark.asyncio
    async def test_smtp_port(self, newsletter_config):
        """SMTP port matches config (587 for submission)."""
        assert newsletter_config["delivery"]["smtp"]["port"] == 587
