import base64
from email.message import EmailMessage
from flask import current_app

import google.auth
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


def gmail_send_message(to: str, subject: str, content: str):
  creds, _ = google.auth.default()

  try:
    service = build("gmail", "v1", credentials=creds)
    message = EmailMessage()

    message.set_content(content)

    message["To"] = to
    message["From"] = "Andre"
    message["Subject"] = subject

    # encoded message
    encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

    create_message = {"raw": encoded_message}
    # pylint: disable=E1101
    send_message = (
        service.users()
        .messages()
        .send(userId="me", body=create_message)
        .execute()
    )
    print(f'Message Id: {send_message["id"]}')
  except HttpError as error:
    print(f"An error occurred: {error}")
    send_message = None
  return send_message


if __name__ == "__main__":
    gmail_send_message("atiagosoares@gmail.com", "Test", "This is a test message")
