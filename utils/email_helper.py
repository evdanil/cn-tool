import smtplib
import logging
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders


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
