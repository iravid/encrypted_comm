from twisted.internet import protocol
from twisted.manhole.telnet import ShellFactory
from zope.interface import implements

from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker, MultiService
from twisted.application import internet

from server.IRPServer import IRPServer, IRPServerFactory

class Options(usage.Options):
    optParameters = [["port", "p", 1235, "The port number to listen on."]]

class IRPServerMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "IRPServer"
    description = "Run this! It'll make your dog happy."
    options = Options

    def makeService(self, options):
        """
        Construct a TCPServer from a factory defined in myproject.
        """
        s = MultiService()

        irp = internet.TCPServer(int(options["port"]), IRPServerFactory())
        irp.setServiceParent(s)

        manholeFactory = ShellFactory()
        manholeFactory.username = "admin"
        manholeFactory.password = "admin"
        manholeFactory.namespace["foo"] = 12
        manholeService = internet.TCPServer(8000, manholeFactory)
        manholeService.setServiceParent(s)

        return s


# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.

serviceMaker = IRPServerMaker()