import struct

__author__ = 'iravid'

class Certificate(object):
    # user_id and username are self-explanatory. public_key is an RSA 2048-bit public key in PEM format
    # An RSA private key can be generated and exported as Crypto.PublicKey.RSA.generate(2048).exportKey("PEM").
    # The public key can be extracted as generate(2048).publickey().exportKey("PEM").
    # user_id <= 2**16 - 1, len(username) <= 64
    def __init__(self, userId, username, publicKey):
        self.userId = userId
        self.username = username
        self.publicKey = publicKey

    # Format: <usernameLength><publicKeyLength><userId><username><publicKey>
    # user_id is 2 bytes, username length is 2 bytes, public key length is 2 bytes
    def serialize(self):
        pkLength = len(self.publicKey)
        usernameLength = len(self.username)

        packed = struct.pack("!HHH", usernameLength, pkLength, self.userId)
        packed += struct.pack("%ds%ds" % (usernameLength, pkLength), self.username, self.publicKey)

        return packed

    @staticmethod
    def deserialize(data):
        usernameLength, pkLength, userId = struct.unpack_from("!HHH", data)

        # The offset here is 6 since struct.calcsize("!HHH") == 6
        username, publicKey = struct.unpack_from("%ds%ds" % (usernameLength, pkLength), data, 6)

        return Certificate(userId, username, publicKey)

