from __future__ import annotations
import smtplib
import logging
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from typing import Any, Optional

from core.base import ScriptContext


def send_report_email(
    logger: logging.Logger,
    smtp_server: str,
    smtp_port: int,
    sender_email: str,
    receiver_email: str,
    subject: str,
    body: str,
    attachment_path: Path,
    use_tls: bool = False,
    use_ssl: bool = False,
    use_auth: bool = False,
    username: str = "",
    password: str = "",
) -> bool:
    """
    Connects to an SMTP server and sends an email with an attachment,
    with optional authentication.
    """
    # Attachment logic is unchanged...
    if not attachment_path.is_file():
        logger.error(f"EMAIL: Attachment file not found at {attachment_path}")
        return False
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    try:
        with open(attachment_path, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename= {attachment_path.name}")
        msg.attach(part)
    except Exception as e:
        logger.error(f"EMAIL: Error attaching file: {e}")
        return False

    # --- Send the email ---
    server = None
    try:
        logger.info(f"EMAIL: Connecting to SMTP server {smtp_server}:{smtp_port}...")
        if use_ssl:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port)
            logger.info("EMAIL: Connected using SSL.")
        else:
            server = smtplib.SMTP(smtp_server, smtp_port)
            logger.info("EMAIL: Connected.")
            if use_tls:
                logger.info("EMAIL: Starting TLS...")
                server.starttls()
                logger.info("EMAIL: TLS started.")

        # <<< NEW LOGIN LOGIC >>>
        if use_auth:
            if username and password:
                logger.info("EMAIL: Logging in with provided credentials...")
                server.login(username, password)
                logger.info("EMAIL: Login successful.")
            else:
                logger.warning("EMAIL: 'use_auth' is true, but username or password is missing. Attempting unauthenticated.")
        else:
            logger.info("EMAIL: Proceeding without login (as configured).")

        # The rest of the sending logic
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)
        logger.info(f"EMAIL: Email successfully sent to {receiver_email}!")
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error("EMAIL: SMTP Authentication Error. Check username/password and server settings (e.g., App Passwords).")
    except smtplib.SMTPConnectError:
        logger.error(f"EMAIL: SMTP Connect Error. Failed to connect to {smtp_server}:{smtp_port}.")
    except Exception as e:
        logger.error(f"EMAIL: An unexpected error occurred: {e}")
    finally:
        if server:
            logger.info("EMAIL: Closing SMTP connection.")
            server.quit()

    return False


def interpret_bool(value: Any) -> bool:
    """Return True when a string or primitive represents a truthy value."""
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "t", "y", "yes", "on"}
    return bool(value)


def send_configured_report(
    ctx: ScriptContext,
    report_path: Any,
    receiver: Optional[str],
    *,
    prefix: str = "EMAIL",
    success_message: Optional[str] = None,
    failure_message: Optional[str] = None,
) -> bool:
    """Send the configured report and perform optional post-send cleanup."""
    logger = ctx.logger
    console = getattr(ctx, "console", None)

    def _console_print(message: str) -> None:
        if console:
            console.print(message)

    if not receiver:
        logger.warning("%s: No recipient configured; skipping email.", prefix)
        _console_print("[red]Error: Email recipient is not configured. Please set 'to' in the [email] section of your config.[/red]")
        return False

    if isinstance(report_path, str):
        report_path = Path(report_path).expanduser()
    if not isinstance(report_path, Path) or not report_path.is_file():
        logger.warning("%s: Report file not found at '%s'. Cannot send email.", prefix, report_path)
        _console_print(f"[red]Error: Report file not found at '{report_path}'. Please generate a report first.[/red]")
        return False

    success = send_report_email(
        logger=logger,
        smtp_server=ctx.cfg.get("email_server", ""),
        smtp_port=int(ctx.cfg.get("email_port", 25)),
        sender_email=ctx.cfg.get("email_from", ""),
        receiver_email=receiver,
        subject=ctx.cfg.get("email_subject", ""),
        body=ctx.cfg.get("email_body", ""),
        attachment_path=report_path,
        use_tls=interpret_bool(ctx.cfg.get("email_use_tls", False)),
        use_ssl=interpret_bool(ctx.cfg.get("email_use_ssl", False)),
        use_auth=interpret_bool(ctx.cfg.get("email_use_auth", False)),
        username=ctx.cfg.get("email_user", ""),
        password=ctx.cfg.get("email_password", ""),
    )

    if success:
        if success_message:
            _console_print(success_message)
        delete_after = interpret_bool(ctx.cfg.get("email_delete_after_send", False))
        logger.info("%s: delete_after_send flag evaluated to %s", prefix, delete_after)
        if delete_after:
            try:
                if report_path.exists():
                    report_path.unlink()
                    _console_print("[green]Report deleted after successful email delivery.[/green]")
                    logger.info("%s: Report deleted after successful delivery.", prefix)
                else:
                    logger.info("%s: Report already removed or missing; nothing to delete.", prefix)
            except OSError as exc:
                logger.warning("%s: Failed to delete report after emailing: %s", prefix, exc)
                _console_print("[yellow]Report email sent, but the report could not be deleted.[/yellow]")
    else:
        if failure_message:
            _console_print(failure_message)

    return success

