import smtplib
from email.mime.text import MIMEText

class Email():
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    def send_email(self, message_string, from_email, recipients = [], subject = ''):
        message = MIMEText(message_string)

        message['Subject'] = subject
        message['From'] = from_email
        message['To'] = '; '.join(recipients)

        server = smtplib.SMTP_SSL(host = self.host, port = self.port)

        server.login(self.username, self.password)
        server.sendmail(from_email, recipients,  message.as_string())
        return True
