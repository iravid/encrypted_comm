from twisted.internet import protocol
from zope.interface import implements

from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker
from twisted.application import internet
from client.IRPClient import IRPClientFactory


class Options(usage.Options):
    optParameters = [
        ["hostname", "h", "localhost", "The hostname to connect to"],
        ["port", "p", 1235, "The port number to connect to."]
    ]

class IRPClientMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "IRPClient"
    description = "Run this! It'll make your dog happy."
    options = Options

    def makeService(self, options):
        """
        Construct a TCPServer from a factory defined in myproject.
        """
        return internet.TCPClient(options["hostname"], int(options["port"]), IRPClientFactory())

# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.

serviceMaker = IRPClientMaker()