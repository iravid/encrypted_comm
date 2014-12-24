import struct

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random

signatureKey = RSA.generate(2048)
encryptionKey = SHA256.new("PASSWORD").digest()

DATA_TYPE = 1

def encryptData(data, key):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return (iv + cipher.encrypt(data)).encode("base64")

def signData(data, key):
    digest = SHA256.new(data)
    return PKCS1_v1_5.new(key).sign(digest)

def constructMessage(data, type, encryptionKey, signatureKey):
    # Encrypt the data
    encryptedData = encryptData(data, encryptionKey)
    dataLength = len(encryptedData)

    # Generate signature
    signature = signData(encryptedData, signatureKey)
    sigLength = len(signature)

    # Generate header
    format = "!BHH"
    header = struct.pack(format, type, dataLength, sigLength)

    return header + encryptedData + signature

def decryptData(data, key):
    data = data.decode("base64")
    iv = data[:16]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.decrypt(data[16:])

def verifySignature(data, sig, key):
    digest = SHA256.new(data)

    return PKCS1_v1_5.new(key).verify(digest, sig)

def decodeMessage(msg, encryptionKey, signatureKey):
    msgType, dataLength, signatureLength = struct.unpack_from("!BHH", msg)
    headerLength = struct.calcsize("!BHH")

    encryptedData = msg[headerLength:headerLength + dataLength]

    signature = msg[-signatureLength:]

    if verifySignature(encryptedData, signature, signatureKey):
        print decryptData(encryptedData, encryptionKey).decode("utf-16")
    else:
        print "Signature failed verification!"




