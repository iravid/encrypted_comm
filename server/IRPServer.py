from Crypto.Util import number
from twisted.python import log

__author__ = 'iravid'

import struct

from Crypto import Random
from Crypto.Random import random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from twisted.internet import protocol

import UserDatabase
from shared.Certificate import Certificate

class ProtocolException(Exception):
    pass

class IncompleteDataException(ProtocolException):
    pass

class BadSignatureException(ProtocolException):
    pass

class IRPServer(protocol.Protocol):
    # Reference prime number and generator from RFC3526, group 17: https://www.ietf.org/rfc/rfc3526.txt
    DIFFIE_HELLMAN_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF
    DIFFIE_HELLMAN_G = 2

    HEADER_FORMAT_STRING = "!BHH"

    SERVER_HEARTBEAT_MAGIC = 0xAA
    CLIENT_HEARTBEAT_MAGIC = 0xCC

    # Message types
    SERVER_HELLO, SERVER_RANDOM, CLIENT_HELLO, CLIENT_RANDOM, SERVER_HEARTBEAT, CLIENT_HEARTBEAT = range(6)

    # Protocol states
    protocolState = None
    WAITING_HELLO, WAITING_RANDOM, WAITING_HEARTBEAT, AUTHENTICATED = range(4)

    # Parsing state
    parseState = None
    PARSING_HEADER, PARSING_DATA, PARSING_SIGNATURE, PARSING_DONE = range(4)

    # Data remaining to be parsed
    remainingData = b""

    # Encrypt the messages being sent?
    encryptMessages = False

    # Verify signatures on received messages?
    verifySignatures = False

    # Encryption keys
    dhPrivateKey = b""
    dhPublicKey = b""
    clientDhPublicKey = b""
    encryptionKey = b""

    # Signature keys
    signatureKey = None
    clientSignatureKey = None

    def makeConnection(self, transport):
        protocol.Protocol.makeConnection(self, transport)

    def connectionMade(self):
        # This table routes parsing states to handling functions
        self.messageDispatchTable = {
            IRPServer.PARSING_HEADER: self.parseHeader,
            IRPServer.PARSING_DATA: self.parseData,
            IRPServer.PARSING_SIGNATURE: self.parseSignature
        }

        # This table routes protocol states to functions initiating the next stage
        self.protocolDispatchTable = {
            IRPServer.CLIENT_HELLO: self.handleClientHello,
            IRPServer.CLIENT_RANDOM: self.handleClientRandom,
            IRPServer.CLIENT_HEARTBEAT: self.handleHeartbeat
        }

        from UserDatabase import _servPrivKey
        self.signatureKey = RSA.importKey(_servPrivKey)

        log.msg("Connection established, sending SERVER_HELLO")
        self.sendServerHello()
        self.parseState = IRPServer.PARSING_HEADER

    def dataReceived(self, data):
        self.remainingData += data

        while self.remainingData:
            if self.parseState == IRPServer.PARSING_DONE:
                self.protocolDispatchTable[self.msgType]()
                self.parseState = IRPServer.PARSING_HEADER

            try:
                self.messageDispatchTable[self.parseState]()
            except IncompleteDataException:
                break

        # When we finish parsing, a packet might not have arrived yet, therefore causing the while loop to not loop
        # again, therefore causing us to miss the protocol dispatch
        if self.parseState == IRPServer.PARSING_DONE:
            self.protocolDispatchTable[self.msgType]()
            self.parseState = IRPServer.PARSING_HEADER

    def encryptData(self, data):
        """
        Encrypt the data using AES with self.encryptionKey and MODE_CFB.
        :param data: The data to be encrypted
        :return: An IV and the encrypted data
        """
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.encryptionKey, AES.MODE_CFB, iv)
        return iv + cipher.encrypt(data)

    def signData(self, data):
        """
        Sign the data using PKCS #1 v1.5, using self.signatureKey and SHA256.
        :param data: The data to be signed
        :return: A PKCS1_v1_5 signature
        """
        digest = SHA256.new(data)
        log.msg("Signing data. Digest is %s" % digest.hexdigest())
        return PKCS1_v1_5.new(self.signatureKey).sign(digest)

    def constructMessage(self, data, type):
        """
        Construct a message with the given data and type. If self.encryptData, encrypt with self.encryptData.
        The message will be signed with self.signData.
        :param data: Data to be stored in the message
        :param type: Message type
        :return: The serialized message
        """
        if self.encryptMessages:
            data = self.encryptData(data)

        data = data.encode("base64")
        dataLength = len(data)

        signature = self.signData(data)
        sigLength = len(signature)

        header = struct.pack(self.HEADER_FORMAT_STRING, type, dataLength, sigLength)

        return header + data + signature

    def sendServerHello(self):
        """
        Send the server certificate.
        """
        serverCert = UserDatabase.getByUserId(0)

        msg = self.constructMessage(serverCert.serialize(), IRPServer.SERVER_HELLO)
        self.transport.write(msg)

        log.msg("Sent SERVER_HELLO")
        self.protocolState = IRPServer.WAITING_HELLO

    def handleClientHello(self):
        """
        Parse out the user ID, username and public key from the message. Check that the username and public key
        match the ones from the user database. Set the user's public key in self.clientSignatureKey.
        Verify the signature on the message and set self.verifySignatures to True. Send the ServerRandom message.
        :return:
        """
        if self.protocolState != IRPServer.WAITING_HELLO:
            raise ProtocolException("Unexpected CLIENT_HELLO received")

        transmittedCert = Certificate.deserialize(self.msgData)
        userCert = UserDatabase.getByUserId(transmittedCert.userId)

        if transmittedCert.username != userCert.username or transmittedCert.publicKey != userCert.publicKey:
            raise ProtocolException("Username or public key not matching the ones stored in the database")

        self.clientSignatureKey = RSA.importKey(transmittedCert.publicKey)

        # Dirty hack - re-encode in base64 to verify the signature
        self.msgData = self.msgData.encode("base64")
        self.verifySignature()
        self.verifySignatures = True

        log.msg("Got CLIENT_HELLO, sending SERVER_RANDOM")

        self.sendServerRandom()

    def sendServerRandom(self):
        """
        Send the server random.
        """
        self.dhPrivateKey = random.getrandbits(576)
        self.dhPublicKey = pow(IRPServer.DIFFIE_HELLMAN_G, self.dhPrivateKey, IRPServer.DIFFIE_HELLMAN_P)

        # Differing from our regular practice of using struct.pack, the dhPublicKey will be sent as a hex-representation.
        data = hex(self.dhPublicKey)
        msg = self.constructMessage(data, IRPServer.SERVER_RANDOM)

        self.transport.write(msg)

        log.msg("Sent SERVER_RANDOM, public key sent was:")
        log.msg(data)

        self.protocolState = IRPServer.WAITING_RANDOM

    def handleClientRandom(self):
        """
        Parse out the client's DH public key and store it as self.clientDhPublickey. Compute the encryption key
        as clientDhPublicKey ^ dhPrivateKey mod DIFFIE_HELLMAN_P. Enable encryption. Start session.
        :return:
        """
        if self.protocolState != IRPServer.WAITING_RANDOM:
            raise ProtocolException("Unexpected CLIENT_RANDOM received")

        self.clientDhPublicKey = long(self.msgData, 16)
        exp = number.long_to_bytes(pow(self.clientDhPublicKey, self.dhPrivateKey, IRPServer.DIFFIE_HELLMAN_P))
        self.encryptionKey = SHA256.new(exp).digest()
        self.encryptMessages = True

        log.msg("Received CLIENT_RANDOM, public key was:")
        log.msg(hex(self.clientDhPublicKey))
        log.msg("Computed encryption key: %s" % SHA256.new(exp).hexdigest())

        self.sendHeartbeat()

    def sendHeartbeat(self):
        """
        Send a predefined magic number.
        :return:
        """
        data = struct.pack("!B", IRPServer.SERVER_HEARTBEAT_MAGIC)
        msg = self.constructMessage(data, IRPServer.SERVER_HEARTBEAT)

        self.transport.write(msg)

        log.msg("Sent heartbeat - %s" % IRPServer.SERVER_HEARTBEAT_MAGIC)

        self.protocolState = IRPServer.WAITING_HEARTBEAT

    def handleHeartbeat(self):
        """
        Test that the number in the message is the client heartbeat magic.
        :return:
        """
        if self.protocolState != IRPServer.WAITING_HEARTBEAT:
            raise ProtocolException("Unexpected CLIENT_HEARTBEAT received")

        magic,  = struct.unpack("!B", self.msgData)
        log.msg("Got heartbeat - %s" % magic)

        if magic != IRPServer.CLIENT_HEARTBEAT_MAGIC:
            raise ProtocolException("Wrong client magic received in heartbeat")

        log.msg("Got valid heartbeat")

        self.startSession()

    def parseHeader(self):
        """
        Attempt to parse a header from self.remainingData. Raise an IncompleteDataException if the size of remainingData
        is smaller than the header size.
        """
        headerSize = struct.calcsize(IRPServer.HEADER_FORMAT_STRING)

        if len(self.remainingData) >= headerSize:
            self.msgType, self.dataLength, self.signatureLength = struct.unpack_from(IRPServer.HEADER_FORMAT_STRING, self.remainingData)
            self.remainingData = self.remainingData[headerSize:]
            self.parseState = IRPServer.PARSING_DATA
        else:
            raise IncompleteDataException()

    def parseData(self):
        if len(self.remainingData) >= self.dataLength:
            self.msgData = self.remainingData[:self.dataLength]
            self.remainingData = self.remainingData[self.dataLength:]
            self.parseState = IRPServer.PARSING_SIGNATURE
        else:
            raise IncompleteDataException()

    def parseSignature(self):
        if len(self.remainingData) >= self.signatureLength:
            self.signatureData = self.remainingData[:self.signatureLength]
            self.remainingData = self.remainingData[self.signatureLength:]
            self.parseState = IRPServer.PARSING_DONE

            if self.verifySignatures:
                self.verifySignature()

            self.msgData = self.msgData.decode("base64")

            if self.encryptMessages:
                self.decryptData()

            self.parseState = IRPServer.PARSING_DONE
        else:
            raise IncompleteDataException()

    def verifySignature(self):
        """
        Verifies that the signature in self.signatureData matches self.msgData
        """
        digest = SHA256.new(self.msgData)

        if not PKCS1_v1_5.new(self.clientSignatureKey).verify(digest, self.signatureData):
            raise BadSignatureException()

    def decryptData(self):
        """
        Decodes self.msgData from base64 and decrypts it using self.encryptionKey
        """
        iv = self.msgData[:16]
        cipher = AES.new(self.encryptionKey, AES.MODE_CFB, iv)
        self.msgData = cipher.decrypt(self.msgData[16:])

    def startSession(self):
        self.protocolState = IRPServer.AUTHENTICATED
        log.msg("Successfully authenticated, starting session")

class IRPServerFactory(protocol.ServerFactory):
    protocol = IRPServer




