import StringIO
from datetime import datetime
import struct
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import random
from Crypto.Signature import PKCS1_v1_5
from Crypto.Util import number
from math import ceil
from twisted.internet import protocol, defer
from twisted.internet.defer import Deferred
from twisted.python import log
from shared.Certificate import Certificate
from shared.Message import Message

__author__ = 'iravid'

_servPubKey = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr0pefsJpu51oWwVWeTto\nMYT9OkMkyLKBiO7N2Fi0QiJEQAC8dBh5A51B8VxHjKjHIDgapIiH3ZYddlJwGy3L\nh0vax8EJKhh4XtaTWPzpu0VbCqD7ShkC9DDKHw/Ipogl2lhz380zdJTyAvsT6UcX\nk1Hgs4yyAxKnmcVlQXgvY9I+4gokHDhSjZD276SDmL3WoqaXQQkg8zqbZHsEZzVk\nh8irgF3IzACj8MY38DJwk5mD9FCpK0KPDA2h+7AaltO75F4v9lgKRNRXGTB3COQ+\nN8v1RrQDV/+v5B0C/BY2cHZfCkOTQtaqxn1wzb32DjdpNISrwVmgieYCVJpCIWB4\nlQIDAQAB\n-----END PUBLIC KEY-----'
_clientPrivKey = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA6VG1LY1SCDPpTjnwblnneK9LnPFMkI8VvNkow/AGIHOoZ2mc
SfahsKPX4iCrHTskASD1nJXDLRyhsRZ+DYNrlP7/AXAiQlms549TR73PeYRLQvJi
rSJN+pzCIy6lqSGm0odYfGeGC5m0CS7xzCk/UQ0dKT91NaOXQ7yJHJ/TJs109CAH
oiv7a544DpPpEp/XQjqShgrT4HurBQOmQK34KRzvczvny/o1Aw06bf7chaWki+0H
RdZuhcBqR7kJK1B0SnzO8Sj8IVglXauAXn6Xgyg3L+xmcliKn/rwFpIti0cEbKZm
FrIuI8Klx5o0LO7aE6vW0ig+MxMd4TX9NPwY9wIDAQABAoIBAQCgUayUqE59pG3j
epxitxP+MTVbmdJqYmclZHJGcF9FXTOSG1dw2y8vGOX2U0xAwapzvBoIhj+ed9YC
wNnMn0kFEFJYwpxHyyar1if7W8l8ThMI5VQ4cyHx2lTrp9nc5Wqjrqx2jwvkXLEA
vmkXSCBhqQkolpoLSWVe/eWY7ZlBRwv/n+miis5aGceebEKWiSTx+H2ZdRlkBL8s
ALsrMHEv8lxh3hH95q7H4XNiMVlc9mCvvqgphc/O0MSwqb8YpUMqJo8H+1nQvaiR
MEehzMA6ZSmd2VFV5RidBW7ELAiC1PU839Vs1zGCXQBTW/4DlNhQM2i9rSRZXDyz
Q9vGV2fBAoGBAPOjm4HdNtiAqKw5rVh4hD8hJlcogSc1QC3+ifpZ1fVaXMCNx5SI
k4dqF20Wa5EwxPKf1B3BRFCAWk5enOl8hYRWOnP5Nskp/g+GWmrlJEtY/6KT//Xd
dS6rZEKRofZdM51HNFPlBkWQKiZVytqPdPeDg8VPg/FB8N17MpWehbFNAoGBAPUo
EJcJj03pr1zZ1fWYLSy8cvd0WlCdDbf2JiG3Bmt/Xr44qqaDKJKupvgGpEh52npP
+PDuDCy62xshGmWdk7RVtd1dTgKwoql4wvVDY9Ym8cF6wL1DZiok5ez/n8hPJzs0
D5ixk7kiIncTDZpJ0wv3MLQ6KSHtclnHSgnjk5FTAoGAcKlKAn4pm2m7FZDCMLPh
61NH6GvJdTjxiZM3eHXMM11qoHuvO2cAWVDcrkv8x7G2kL8JlgzFqzf/ClhD1NAI
6Y36D6DBDbqGSeWFsAJviwwHgcVQSf/y7PbCMOoo68RjVqoTb2vrP4WPiBSJ7hEC
NGYzK60+RPSKDdCnLnqUNc0CgYEA1tKo1vEVlhx0AlUQXAlhbJYl2BkpGwLEhrM3
bsvG4GPYTa+yOf8sinxo62ZGhwvgGtYBOn4eRQPoA7naO7j9OUTx/GxKc6j8oKyl
ie3nijzOE9DRHAf3em6i3C6TgR97LTHNiOvymoQC13zmqpCOUynkj8l3SbecQHeV
tVyqbukCgYALQIe1J/JRWtLMiZlc0bjOY0tArdMkQWBQ7rEA4lQtd1eT7HlJmeEp
nGnPZOr97FF+ThVgiWdjzKLkJrtwbV1e5Z+sykZWgJTyoghyIT+qR40NNkkx4/m4
PiKVvFxJWwAP74WWe+4jmjJA1d21GeESKAjnd32e4qj0GdZ3U/rs4w==
-----END RSA PRIVATE KEY-----"""
_clientCert = "\x00\x06\x01\xc2\x00\x01iravid-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6VG1LY1SCDPpTjnwblnn\neK9LnPFMkI8VvNkow/AGIHOoZ2mcSfahsKPX4iCrHTskASD1nJXDLRyhsRZ+DYNr\nlP7/AXAiQlms549TR73PeYRLQvJirSJN+pzCIy6lqSGm0odYfGeGC5m0CS7xzCk/\nUQ0dKT91NaOXQ7yJHJ/TJs109CAHoiv7a544DpPpEp/XQjqShgrT4HurBQOmQK34\nKRzvczvny/o1Aw06bf7chaWki+0HRdZuhcBqR7kJK1B0SnzO8Sj8IVglXauAXn6X\ngyg3L+xmcliKn/rwFpIti0cEbKZmFrIuI8Klx5o0LO7aE6vW0ig+MxMd4TX9NPwY\n9wIDAQAB\n-----END PUBLIC KEY-----"


class ProtocolException(Exception):
    pass
class IncompleteDataException(ProtocolException):
    pass
class BadSignatureException(ProtocolException):
    pass

class IRPClient(protocol.Protocol):
    # Reference prime number and generator from RFC3526, group 17: https://www.ietf.org/rfc/rfc3526.txt
    DIFFIE_HELLMAN_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF
    DIFFIE_HELLMAN_G = 2

    HEADER_FORMAT_STRING = "!BHH"
    # digestLength (H), transmitSize (H), hexDigest (appended string)
    TRANSMIT_HEADERS_FORMAT_STRING = "!HH"

    TRANSMIT_CHUNK_SIZE = 1024

    # Message types
    SERVER_HELLO, SERVER_RANDOM, CLIENT_HELLO, CLIENT_RANDOM, SERVER_HEARTBEAT, CLIENT_HEARTBEAT, USER_LIST_REQUEST,\
        USER_LIST_RESPONSE, TRANSMIT_HEADERS, TRANSMIT_START, TRANSMIT_CHUNK, RECEIVED_CHUNK, TRANSMIT_SUCCESS,\
        TRANSMIT_FAILURE, MESSAGE_LIST_REQUEST, MESSAGE_LIST_RESPONSE, MESSAGE_RETRIEVE_REQUEST = range(17)

    # Protocol states
    protocolState = None
    WAITING_HELLO, WAITING_RANDOM, WAITING_HEARTBEAT, AUTHENTICATED, SENDING_FILE, RECEIVING_FILE = range(6)

    # Parse states
    parseState = None
    PARSING_HEADER, PARSING_DATA, PARSING_SIGNATURE, PARSING_DONE = range(4)

    SERVER_HEARTBEAT_MAGIC = 0xAA
    CLIENT_HEARTBEAT_MAGIC = 0xCC

    # Data remaining to be parsed
    remainingData = b""

    # Server key is preloaded, so signatures can be verified from the start
    verifySignatures = True
    encryptMessages = False

    def connectionMade(self):
        self.messageDispatchTable = {
            IRPClient.PARSING_HEADER: self.parseHeader,
            IRPClient.PARSING_DATA: self.parseData,
            IRPClient.PARSING_SIGNATURE: self.parseSignature
        }

        self.protocolDispatchTable = {
            IRPClient.SERVER_HELLO: self.handleServerHello,
            IRPClient.SERVER_RANDOM: self.handleServerRandom,
            IRPClient.SERVER_HEARTBEAT: self.handleHeartbeat,
            IRPClient.USER_LIST_RESPONSE: self.handleUserListResponse,
            IRPClient.TRANSMIT_START: self.handleTransmitStart,
            IRPClient.RECEIVED_CHUNK: self.handleReceivedChunk,
            IRPClient.TRANSMIT_SUCCESS: self.handleTransmitSuccess,
            IRPClient.TRANSMIT_FAILURE: self.handleTransmitFailure,
            IRPClient.TRANSMIT_HEADERS: self.handleTransmitHeaders,
            IRPClient.TRANSMIT_CHUNK: self.handleTransmitChunk,
            IRPClient.MESSAGE_LIST_RESPONSE: self.handleMessageListResponse
        }

        self.factory.clientConnectionMade(self)

        self.clientCert = self.factory.clientCert
        self.signatureKey = self.factory.signatureKey
        self.serverSignatureKey = self.factory.serverSignatureKey
        self.protocolState = IRPClient.WAITING_HELLO

        log.msg("Connection established, waiting for SERVER_HELLO")
        self.parseState = IRPClient.PARSING_HEADER

    def dataReceived(self, data):
        log.msg("Entered dataReceived with data:")
        log.msg(data)
        self.remainingData += data

        while self.remainingData:
            if self.parseState == IRPClient.PARSING_DONE:
                log.msg("Parsing done, dispatching to %s" % self.protocolDispatchTable[self.msgType])
                self.protocolDispatchTable[self.msgType]()
                self.parseState = IRPClient.PARSING_HEADER

            try:
                self.messageDispatchTable[self.parseState]()
            except IncompleteDataException:
                log.msg("Incomplete data in packet")
                break

        # Ugly structure. We'll live with it for now. This is needed since we might finish parsing the packet without
        # another packet waiting, in which case the remainingData loop won't loop again.
        if self.parseState == IRPClient.PARSING_DONE:
            log.msg("Parsing done, dispatching to %s" % self.protocolDispatchTable[self.msgType])
            self.protocolDispatchTable[self.msgType]()
            self.parseState = IRPClient.PARSING_HEADER


    # Message parsing stuff
    def parseHeader(self):
        log.msg("Entered parseHeader")
        headerSize = struct.calcsize(IRPClient.HEADER_FORMAT_STRING)

        if len(self.remainingData) >= headerSize:
            self.msgType, self.dataLength, self.signatureLength = struct.unpack_from(IRPClient.HEADER_FORMAT_STRING, self.remainingData)
            log.msg("Parsed fields: msgType = %d, dataLength = %d, sigLength = %d" % (self.msgType, self.dataLength, self.signatureLength))
            self.remainingData = self.remainingData[headerSize:]
            self.parseState = IRPClient.PARSING_DATA
        else:
            raise IncompleteDataException()

    def parseData(self):
        log.msg("Entered parseData")
        if len(self.remainingData) >= self.dataLength:
            self.msgData = self.remainingData[:self.dataLength]
            log.msg("Read %d bytes" % len(self.msgData))
            self.remainingData = self.remainingData[self.dataLength:]
            self.parseState = IRPClient.PARSING_SIGNATURE
        else:
            raise IncompleteDataException()

    def parseSignature(self):
        log.msg("Entered parseSignature, verifySignatures is %s and encryptMessages is %s" % (self.verifySignatures, self.encryptMessages))
        if len(self.remainingData) >= self.signatureLength:
            self.signatureData = self.remainingData[:self.signatureLength]
            self.remainingData = self.remainingData[self.signatureLength:]
            self.parseState = IRPClient.PARSING_DONE

            log.msg("Read %d bytes" % len(self.signatureData))

            if self.verifySignatures:
                self.verifySignature()

            self.msgData = self.msgData.decode("base64")
            log.msg("Data after base64 decoding: %d bytes" % len(self.msgData))

            if self.encryptMessages:
                self.decryptData()

            log.msg("Leaving parseSignature")
            self.parseState = IRPClient.PARSING_DONE
        else:
            raise IncompleteDataException()

    # Encryption stuff
    def verifySignature(self):
        digest = SHA256.new(self.msgData)

        log.msg("Entered verify signature, digest is %s" % digest.hexdigest())

        if not PKCS1_v1_5.new(self.serverSignatureKey).verify(digest, self.signatureData):
            raise BadSignatureException()

    def decryptData(self):
        iv = self.msgData[:16]
        cipher = AES.new(self.encryptionKey, AES.MODE_CFB, iv)
        self.msgData = cipher.decrypt(self.msgData[16:])

    def encryptData(self, data):
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.encryptionKey, AES.MODE_CFB, iv)
        return iv + cipher.encrypt(data)

    def signData(self, data):
        digest = SHA256.new(data)
        return PKCS1_v1_5.new(self.signatureKey).sign(digest)

    # Protocol handling messages
    def constructMessage(self, data, type):
        if self.encryptMessages:
            data = self.encryptData(data)

        data = data.encode("base64")
        dataLength = len(data)

        signature = self.signData(data)
        sigLength = len(signature)

        header = struct.pack(self.HEADER_FORMAT_STRING, type, dataLength, sigLength)

        return header + data + signature

    def handleServerHello(self):
        serverCert = Certificate.deserialize(self.msgData)

        # Just a quick sanity check:
        if serverCert.publicKey != _servPubKey:
            raise Exception()

        log.msg("Got a SERVER_HELLO message, certificate contained uid %d and username %s" % (serverCert.userId, serverCert.username))

        self.sendClientHello()

    def sendClientHello(self):
        # Format: <otp(I)><certificate>
        data = struct.pack("!I", self.factory.otpValue)
        data += self.clientCert.serialize()

        msg = self.constructMessage(data, IRPClient.CLIENT_HELLO)
        self.transport.write(msg)

        log.msg("Sent CLIENT_HELLO with OTP %d" % self.factory.otpValue)

        self.protocolState = IRPClient.WAITING_RANDOM

    def handleServerRandom(self):
        self.dhPrivateKey = random.getrandbits(576)
        self.dhPublicKey = pow(IRPClient.DIFFIE_HELLMAN_G, self.dhPrivateKey, IRPClient.DIFFIE_HELLMAN_P)

        self.serverDhPublicKey = long(self.msgData, 16)

        exp = number.long_to_bytes(pow(self.serverDhPublicKey, self.dhPrivateKey, IRPClient.DIFFIE_HELLMAN_P))
        self.encryptionKey = SHA256.new(exp).digest()

        log.msg("Got SERVER_RANDOM. Server's public key was:")
        log.msg(hex(self.serverDhPublicKey))
        log.msg("Computed encryption key: %s" % SHA256.new(exp).hexdigest())

        self.sendClientRandom()

    def sendClientRandom(self):
        data = hex(self.dhPublicKey)
        msg = self.constructMessage(data, IRPClient.CLIENT_RANDOM)

        self.transport.write(msg)
        self.encryptMessages = True

        log.msg("Sent CLIENT_RANDOM, messages are now encrypted")

        self.protocolState = IRPClient.WAITING_HEARTBEAT

    def handleHeartbeat(self):
        magic, = struct.unpack("!B", self.msgData)
        log.msg("Got heartbeat: %s" % magic)

        if magic != IRPClient.SERVER_HEARTBEAT_MAGIC:
            raise ProtocolException("Bad heartbeat received")

        log.msg("Got valid heartbeat")

        self.sendHeartbeat()

    def sendHeartbeat(self):
        data = struct.pack("!B", IRPClient.CLIENT_HEARTBEAT_MAGIC)
        msg = self.constructMessage(data, IRPClient.CLIENT_HEARTBEAT)

        self.transport.write(msg)

        log.msg("Sent heartbeat - %s" % IRPClient.CLIENT_HEARTBEAT_MAGIC)

        self.startSession()

    def startSession(self):
        self.protocolState = IRPClient.AUTHENTICATED
        log.msg("Authenticated successfully, session started")
        self.factory.clientConnectionAuthenticated()

    def sendUserListRequest(self):
        msg = self.constructMessage("", IRPClient.USER_LIST_REQUEST)
        self.transport.write(msg)

        self.nextDeferred = Deferred()
        return self.nextDeferred

    def handleUserListResponse(self):
        userList = self.msgData.split("\n")
        self.nextDeferred.callback(userList)

    # Methods for handling an incoming file transmission
    def handleTransmitHeaders(self):
        """
        Server has indicated a file transmission is about to occur and has sent the headers. Parse them out, set
        protocol state to RECEIVING_FILE and send a response.
        """
        assert self.protocolState == IRPClient.AUTHENTICATED

        buffer = self.msgData

        digestLength, self._transmitChunksLeft = struct.unpack_from(IRPClient.TRANSMIT_HEADERS_FORMAT_STRING, buffer)
        buffer = buffer[struct.calcsize(IRPClient.TRANSMIT_HEADERS_FORMAT_STRING):]

        self._transmitHexDigest = buffer[:digestLength]

        self._fileInTransmit = StringIO.StringIO()

        self.protocolState = IRPClient.RECEIVING_FILE
        self.sendTransmitStart()

    def sendTransmitStart(self):
        """
        Indicate to server that the transmit may start.
        """
        msg = self.constructMessage("", IRPClient.TRANSMIT_START)
        self.transport.write(msg)

    def handleTransmitChunk(self):
        """
        Read a chunk. If enough chunks were read, verify the digest. If not, send a RECEIVED_CHUNK message.
        """
        assert self.protocolState == IRPClient.RECEIVING_FILE

        if self._transmitChunksLeft <= 0:
            raise ProtocolException("Unexpected chunk received")

        self._fileInTransmit.write(self.msgData)
        self._transmitChunksLeft -= 1

        if self._transmitChunksLeft > 0:
            self.sendReceivedChunk()
        else:
            self.verifyFileDigest()

    def sendReceivedChunk(self):
        """
        Indicate to server that another chunk may be sent.
        """
        msg = self.constructMessage("", IRPClient.RECEIVED_CHUNK)
        self.transport.write(msg)

    def verifyFileDigest(self):
        """
        Compare the received file's SHA256 digest to the pretransmitted digest. If they are identical,
        send a TRANSMIT_SUCCESS message. If not, send a TRANSMIT_FAILURE message.
        """
        digest = SHA256.new(self._fileInTransmit.getvalue()).hexdigest()

        if digest == self._transmitHexDigest:
            self.sendTransmitSuccess()
        else:
            self.sendTransmitFailure()

    def sendTransmitSuccess(self):
        """
        Inform the server of the transmit sucess and call the received file callback.
        """
        msg = self.constructMessage("", IRPClient.TRANSMIT_SUCCESS)
        self.transport.write(msg)

        self.nextDeferred.callback(self._fileInTransmit.getvalue())

        # Remove state variables and return to AUTHENTICATED state
        self._fileInTransmit = None
        self._transmitChunksLeft = None
        self._transmitHexDigest = None
        self.protocolState = IRPClient.AUTHENTICATED

    def sendTransmitFailure(self):
        """
        Inform the server of the transmit failure and call the received file errback.
        """
        msg = self.constructMessage("", IRPClient.TRANSMIT_FAILURE)
        self.transport.write(msg)

        self.nextDeferred.errback(False)

        # Remove state variables and return to AUTHENTICATED state
        self._fileInTransmit = None
        self._transmitChunksLeft = None
        self._transmitHexDigest = None
        self.protocolState = IRPClient.AUTHENTICATED

    # Methods for handling an outgoing file transmission
    def sendFile(self, file, length, hexDigest):
        """
        Send a file to the server.
        :param file: A file-like object containing the file data.
        :param length: The length of the file.
        :param hexDigest: The SHA256 hex-digest of the file data.
        """
        self._fileInTransmit = file
        self._transmitSize = int(ceil(float(length) / IRPClient.TRANSMIT_CHUNK_SIZE))
        self._transmitHexDigest = hexDigest

        self.protocolState = IRPClient.SENDING_FILE
        self.sendFileHeaders()

        self.nextDeferred = Deferred()
        return self.nextDeferred

    def sendFileHeaders(self):
        """
        Send the headers message in the following format:
        <hexDigestLength><transmitChunkAmount><hexDigest>
        """
        data = struct.pack(IRPClient.TRANSMIT_HEADERS_FORMAT_STRING, len(self._transmitHexDigest), self._transmitSize)
        data += self._transmitHexDigest

        msg = self.constructMessage(data, IRPClient.TRANSMIT_HEADERS)
        self.transport.write(msg)

    def handleTransmitStart(self):
        """
        Server has indicated that we can start transmitting the file.
        """
        assert self.protocolState == IRPClient.SENDING_FILE
        self.sendTransmitChunk()

    def handleReceivedChunk(self):
        """
        Server has indicated we can send the next chunk.
        """
        assert self.protocolState == IRPClient.SENDING_FILE
        self.sendTransmitChunk()

    def sendTransmitChunk(self):
        """
        Send another TRANSMIT_CHUNK_SIZE bytes of the file.
        """
        chunkData = self._fileInTransmit.read(IRPClient.TRANSMIT_CHUNK_SIZE)

        if chunkData:
            msg = self.constructMessage(chunkData, IRPClient.TRANSMIT_CHUNK)
            self.transport.write(msg)

    def handleTransmitSuccess(self):
        """
        Server has indicated that the transfer was successful. Change state to AUTHENTICATED.
        """
        assert self.protocolState == IRPClient.SENDING_FILE
        assert not self._fileInTransmit.read(IRPClient.TRANSMIT_CHUNK_SIZE)
        log.msg("Transmit successful")

        self._fileInTransmit = None
        self._transmitSize = None
        self._transmitHexDigest = None

        self.protocolState = IRPClient.AUTHENTICATED

        self.nextDeferred.callback(True)

    def handleTransmitFailure(self):
        """
        Client has indicated that the transfer failed. Change state to AUTHENTICATED.
        """
        assert self.protocolState == IRPClient.SENDING_FILE
        assert not self._fileInTransmit.read(IRPClient.TRANSMIT_CHUNK_SIZE)
        log.msg("Transmit failure")

        self._fileInTransmit = None
        self._transmitSize = None
        self._transmitHexDigest = None

        self.protocolState = IRPClient.AUTHENTICATED

        self.nextDeferred.errback(False)

    def sendMessageListRequest(self):
        """
        Request the list of messages currently in the mailbox from the server.
        """
        msg = self.constructMessage("", IRPClient.MESSAGE_LIST_REQUEST)
        self.transport.write(msg)

        self.nextDeferred = Deferred()
        return self.nextDeferred


    def handleMessageListResponse(self):
        """
        Handle the list of message IDs and sizes from the server.
        """

        msgSizes = self.msgData.split("\n") if self.msgData else None
        self.nextDeferred.callback(msgSizes)

    def sendMessageRetrieveRequest(self, msgId):
        """
        Request a specific message from the server. The response is handled by the incoming file flow.
        :param msgId: The index of the requested message
        """
        log.msg("Retrieving message with id %d" % msgId)

        data = struct.pack("!H", msgId)
        msg = self.constructMessage(data, IRPClient.MESSAGE_RETRIEVE_REQUEST)
        self.transport.write(msg)

        self.nextDeferred = Deferred()
        return self.nextDeferred

class IRPClientFactory(protocol.ClientFactory):
    def __init__(self, clientCert, clientPrivKey, serverSignatureKey=_servPubKey):
        self.ready = False
        self.clientCert = clientCert
        self.signatureKey = clientPrivKey
        self.serverSignatureKey = RSA.importKey(serverSignatureKey)

    def buildProtocol(self, addr):
        client = IRPClient()
        client.factory = self
        self.client = client

        return client

    def clientConnectionMade(self, p):
        pass

    def clientConnectionAuthenticated(self):
        self.ready = True

    def responseReceived(self, result):
        """
        Generic callback to set _ready to True once a response has been received.
        """
        self.ready = True
        return result

    def listUsers(self):
        """
        Request a user list from the server.
        :return: A Deferred which will fire with a user list.
        """
        if not self.ready:
            log.err("Action called when not ready")
            return defer.fail()

        self.ready = False
        d = self.client.sendUserListRequest()
        d.addCallback(self.responseReceived)

        return d

    def listMessages(self):
        """
        Request a message list from the server.
        :return: A Deferred which will fire with a list of message sizes.
        """
        if not self.ready:
            log.err("Action called when not ready")
            return defer.fail()

        self.ready = False
        d = self.client.sendMessageListRequest()
        d.addCallback(self.responseReceived)

        return d

    def sendMessage(self, msgData, length, hexDigest):
        """
        Send a message to the server.
        :param msgData: A file-like object with the data.
        :param length: Length of the data in bytes
        :param hexDigest: SHA256 hex-digest of the data
        :return: A Deferred which will fire when the message has been sent.
        """
        if not self.ready:
            log.err("Action called when not ready")
            return defer.fail()

        self.ready = False
        d = self.client.sendFile(msgData, length, hexDigest)
        d.addCallback(self.responseReceived)

        return d

    def retrieveMessage(self, msgId):
        """
        Retrieve a message from the server.
        :param msgId: ID of the desired message.
        :return: A Deferred which will fire with a file-like object containing the message data.
        """
        if not self.ready:
            log.err("Action called when not ready")
            return defer.fail()

        log.msg("In factory.retrieveMessage with %d" % msgId)

        self.ready = False
        d = self.client.sendMessageRetrieveRequest(msgId)
        d.addCallback(self.responseReceived)

        return d
