from backend.app.schemas.email_message import NormalizedEmail
from backend.app.schemas.m1 import M1Input


def prepare_m1_input(email: NormalizedEmail) -> M1Input:
    return M1Input(
        sender=email.sender,
        reply_to=email.reply_to,
        return_path=email.return_path,
        received_headers=email.received_headers,
        received_spf=email.received_spf,
        authentication_results=email.authentication_results,
        body=email.body,
        urls=email.urls,
        attachments=[a.model_dump() for a in email.attachments],
    )
