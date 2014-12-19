import StringIO
from datetime import datetime

__author__ = 'iravid'

class Message(object):
    TIMESTAMP_FORMAT = "%d/%m/%Y %H:%M:%S"

    def __init__(self, author, recipients, timestamp, subject, content):
        """
        :param author: The username of the author.
        :param recipients: A list of recipient usernames.
        :param timestamp: A datetime object containing the time the message was written.
        :param subject: The subject of the message.
        :param content: The message contents.
        :return:
        """
        self.author = author
        self.recipients = recipients
        self.timestamp = timestamp
        self.subject = subject
        self.content = content

    def __str__(self):
        return self.serialize()

    def serialize(self):
        output = StringIO.StringIO()
        output.write("From: %s\n" % self.author)
        output.write("To: %s\n" % ", ".join(self.recipients))
        output.write("Timestamp: %s\n" % self.timestamp.strftime(Message.TIMESTAMP_FORMAT))
        output.write("Subject: %s\n" % self.subject)
        output.write(self.content)

        return output.getvalue()

    @staticmethod
    def deserialize(data):
        author = data.readline().split(": ")[1]
        recipients = data.readline().split(": ")[1].split(", ")
        timestamp = datetime.strptime(data.readline().split(": ")[1], Message.TIMESTAMP_FORMAT)
        subject = data.readline().split(": ")[1]
        content = data.read()

        return Message(author, recipients, timestamp, subject, content)
