from datetime import datetime
from Crypto.Hash import SHA256
from StringIO import StringIO
import sys
from Crypto.PublicKey import RSA
from twisted.python import log
import urwid

from twisted.internet import reactor
from client.IRPClient import IRPClientFactory
from shared.Certificate import Certificate
from shared.Message import Message

__author__ = 'iravid'

class ShowMessage(urwid.WidgetWrap):
    def __init__(self, view, author, recipients, timestamp, subject, content):
        self.view = view

        self.title_text = urwid.Text("Showing Message")
        self.from_text = urwid.Text("From: %s" % self.view.username)
        self.to_text = urwid.Text("To: %s" % recipients)
        self.subject_text = urwid.Text("Subject: %s" % subject)
        self.content_text = urwid.Text(content)

        self.close_button = urwid.Button("Close")
        urwid.connect_signal(self.close_button, "click", self.close)

        self.header = urwid.LineBox(urwid.Pile([self.title_text, self.from_text, self.to_text, self.subject_text]))
        self.footer = urwid.LineBox(urwid.GridFlow([self.close_button], 12, 2, 0, "right"))

        self.frame = urwid.Frame(urwid.Filler(urwid.LineBox(self.content_text), valign="top"), header=self.header, footer=self.footer, focus_part="footer")

        urwid.WidgetWrap.__init__(self, self.frame)

    def close(self, _=None):
        self.view.show_message_list()

class ComposeMessage(urwid.WidgetWrap):
    def __init__(self, view):
        self.view = view

        self.title_text = urwid.Text("New Message")
        self.from_text = urwid.Text("From: %s" % self.view.username)
        self.to_edit = urwid.Edit("To: ")
        self.subject_edit = urwid.Edit("Subject: ")
        self.content_edit = urwid.Edit(multiline=True)

        self.submit_button = urwid.Button("Submit")
        urwid.connect_signal(self.submit_button, "click", self.submit)

        self.discard_button = urwid.Button("Discard")
        urwid.connect_signal(self.discard_button, "click", self.discard)

        self.header = urwid.LineBox(urwid.Pile([self.title_text, self.from_text, self.to_edit, self.subject_edit]))
        self.footer = urwid.LineBox(urwid.GridFlow([self.submit_button, self.discard_button], 12, 2, 0, "right"))

        self.frame = urwid.Frame(urwid.Filler(urwid.LineBox(self.content_edit), valign="top"), header=self.header, footer=self.footer, focus_part="header")

        urwid.WidgetWrap.__init__(self, self.frame)

    def keypress(self, size, key):
        if key != 'tab':
            return super(urwid.WidgetWrap, self).keypress(size, key)

        if self.frame.focus_position == "header":
            self.frame.focus_position = "body"
        elif self.frame.focus_position == "body":
            self.frame.focus_position = "footer"
        elif self.frame.focus_position == "footer":
            self.frame.focus_position = "header"

    def submit(self, _=None):
        self.view.done_composing(self.to_edit.edit_text, self.subject_edit.edit_text, self.content_edit.edit_text)

    def discard(self, _=None):
        self.view.show_message_list()

class MessageEntry(urwid.WidgetWrap):
    _selectable = True

    def __init__(self, author, subject, timestamp):
        self.author_text = urwid.Text(author)
        self.subject_text = urwid.Text(subject)
        self.timestamp_text = urwid.Text(timestamp)

        self.cols = urwid.Columns([("weight", 15, self.author_text),
                       ("weight", 70, self.subject_text),
                       ("weight", 15, self.timestamp_text)])

        super(MessageEntry, self).__init__(urwid.AttrMap(self.cols, None, focus_map="reversed"))

    def selectable(self):
        return True

    def keypress(self, size, key):
        return key


class MessageList(urwid.WidgetWrap):
    def __init__(self, view, entries=[]):
        self.contents = urwid.SimpleFocusListWalker(entries)
        self.listbox = urwid.ListBox(self.contents)

        self.view = view

        urwid.WidgetWrap.__init__(self, urwid.LineBox(self.listbox))

    def keypress(self, size, key):
        if key == "n":
            self.view.compose_message()
            return
        elif key == "l":
            self.view.refresh_messages()
            return
        elif key == "enter":
            self.view.show_message(self.contents.focus)
        else:
            return super(MessageList, self).keypress(size, key)

    def add_entry(self, entry):
        self.contents.append(entry)

    def clear_entries(self):
        # No clear() implemented on SimpleFocusListWalker...
        del self.contents[:]

class OTPInput(urwid.WidgetWrap):
    def __init__(self, view):
        self.value_edit = urwid.Edit("Enter the current OTP value: ")

        self.connect_button = urwid.Button("Connect")
        urwid.connect_signal(self.connect_button, "click", self.connect)

        self.pile = urwid.Pile([self.value_edit, self.connect_button])

        self.view = view

        super(OTPInput, self).__init__(urwid.Filler(self.pile))

    def connect(self, _=None):
        self.view.done_otp(long(self.value_edit.edit_text))

class View(object):
    def __init__(self, username):
        self.username = username

        self.status_text = urwid.Text("")
        self.message_list = MessageList(self)
        self.otp_input = OTPInput(self)
        self.window = urwid.Frame(self.otp_input, footer=urwid.LineBox(self.status_text))

        self.palette = [("reversed", "standout", "")]

    def show_message_list(self):
        self.update_status("%d messages." % len(self.message_list.contents))
        self.window.body = self.message_list

    def refresh_messages(self):
        self.controller.refresh_messages()

    def update_message_list(self, messages):
        self.message_list.clear_entries()

        for msg in messages:
            msg_entry = MessageEntry(msg.author, msg.subject, msg.timestamp.strftime(Message.TIMESTAMP_FORMAT))
            self.message_list.add_entry(msg_entry)
            log.msg("Added a message entry for message with subject %s" % msg.subject)
            self.loop.draw_screen()

        self.update_status("Done fetching messages. %d messages in mailbox." % len(messages))

    def show_message(self, index):
        self.update_status("Showing message")
        m = self.controller.messages[index]
        self.window.body = ShowMessage(self, m.author, ", ".join(m.recipients), m.timestamp.strftime(Message.TIMESTAMP_FORMAT), m.subject, m.content)

    def compose_message(self):
        self.update_status("Composing new message")
        self.window.body = ComposeMessage(self)

    def done_composing(self, recipients, subject, content):
        self.controller.send_message(recipients, subject, content)
        self.show_message_list()

    def done_otp(self, value):
        self.show_message_list()
        self.controller.connect(value)

    def update_status(self, text):
        self.status_text.set_text(text)
        self.loop.draw_screen()

    def unhandled_input(self, key):
        if key in ('q', 'Q'):
            raise urwid.ExitMainLoop()

class Controller(object):
    def __init__(self):
        self.messages = []

    def refresh_messages(self):
        if not self.factory.ready:
            reactor.callLater(2, self.refresh_messages)
            return

        self.view.update_status("Refreshing message list")

        self.messages = []

        d = self.factory.listMessages()
        d.addCallback(self.download_messages)

    def download_messages(self, msg_list):
        log.msg("Entered download_messages with %s" % msg_list)

        if msg_list:
            enumerated = list(enumerate(msg_list))
            d = self.factory.retrieveMessage(enumerated[0][0])
            d.addCallback(self.got_message, enumerated)
        else:
            self.view.update_message_list(self.messages)

    def got_message(self, msg_data, enumerated_msg_list):
        log.msg("Entered got_message with msg_data:")
        log.msg(msg_data)
        log.msg("And msg_list: %s" % enumerated_msg_list)

        self.messages.append(Message.deserialize(msg_data))
        log.msg("Messages is now %s" % self.messages)
        enumerated_msg_list.pop(0)
        log.msg("msg_list is now %s" % enumerated_msg_list)

        if enumerated_msg_list:
            log.msg("Downloading the next message: %s" % enumerated_msg_list[0][0])
            d = self.factory.retrieveMessage(enumerated_msg_list[0][0])
            d.addCallback(self.got_message, enumerated_msg_list)
        else:
            log.msg("Done downloading. Updating the message list")
            self.view.update_message_list(self.messages)

    def send_message(self, recipients, subject, content):
        m = Message(self.factory.clientCert.username, recipients.split(", "), datetime.now(), subject, content).serialize()
        length = len(m)
        digest = SHA256.new(m).hexdigest()

        self.factory.sendMessage(StringIO(m), length, digest)

    def connect(self, otp_value):
        self.view.update_status("Connecting...")
        self.factory.otpValue = otp_value
        reactor.connectTCP("localhost", 1235, self.factory)
        self.refresh_messages()

class Client(object):
    def __init__(self, username):
        self.clientCert = Certificate.deserialize(open("%s.cert" % username).read())
        self.signatureKey = RSA.importKey(open("%s.priv" % username).read())

        self.factory = IRPClientFactory(self.clientCert, self.signatureKey)
        self.controller = Controller()
        self.view = View(self.factory.clientCert.username)

        self.controller.view = self.view
        self.controller.factory = self.factory
        self.view.controller = self.controller

        self.loop = urwid.MainLoop(self.view.window, self.view.palette,
                                   unhandled_input=self.view.unhandled_input,
                                   event_loop=urwid.TwistedEventLoop())
        self.view.loop = self.loop

    def run(self):
        log.startLogging(open("client.log", "w"))
        self.loop.run()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: %s <username>" % sys.argv[0]

    c = Client(sys.argv[1])
    c.run()