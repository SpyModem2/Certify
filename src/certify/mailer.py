from __future__ import annotations

import smtplib
from email.message import EmailMessage


def send_local_mail(host: str, port: int, sender: str, recipient: str, subject: str, body: str) -> None:
    """Send through the configured local relay; authentication remains relay-side."""
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = sender, recipient, subject
    message.set_content(body)
    with smtplib.SMTP(host, port, timeout=10) as smtp:
        smtp.send_message(message)
