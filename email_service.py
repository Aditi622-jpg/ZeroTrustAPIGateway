import os
from dotenv import load_dotenv
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType

load_dotenv()

conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    MAIL_PORT=int(os.getenv("MAIL_PORT", 587)),
    MAIL_SERVER=os.getenv("MAIL_SERVER", "smtp.gmail.com"),
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)


async def send_otp_email(email: str, otp: str):

    message = MessageSchema(
        subject="Zero Trust API Gateway - OTP Verification",
        recipients=[email],
        body=f"""
Hello,

Your OTP for Zero Trust API Gateway login is: {otp}

This OTP is valid for 5 minutes.

Please do not share this code with anyone.

Regards,
Zero Trust API Gateway Security Team
""",
        subtype=MessageType.plain
    )

    mail = FastMail(conf)

    await mail.send_message(message)