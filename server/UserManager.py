import os
import subprocess
import sys
from Crypto.PublicKey import RSA
import pyotp
import pyqrcode
from server import UserDatabase
from server.Configuration import CERTIFICATE_DIRECTORY
from shared.Certificate import Certificate

__author__ = 'iravid'

def createNewUser(username):
    userPrivKey = RSA.generate(2048)
    userPubKey = userPrivKey.publickey()

    # Write out the private key
    open(os.path.join(CERTIFICATE_DIRECTORY, "%s.priv" % username), "w").write(userPrivKey.exportKey("PEM"))
    print "Private key written to %s" % os.path.join(CERTIFICATE_DIRECTORY, "%s.priv" % username)

    # Create a certificate
    userId = UserDatabase.getNextId()
    userCert = Certificate(userId, username, userPubKey.exportKey("PEM"))

    # Write out certificate
    open(os.path.join(CERTIFICATE_DIRECTORY, "%s.cert" % username), "w").write(userCert.serialize())
    print "Certificate written to %s" % os.path.join(CERTIFICATE_DIRECTORY, "%s.cert" % username)

    # Generate an OTP secret
    secret = pyotp.random_base32()
    UserDatabase.addOtpSecret(userCert, secret)

    # Display provisioning URI using a QR code:
    uri = pyotp.TOTP(secret).provisioning_uri("%s@IRP" % username)
    qr = pyqrcode.create(uri)
    qr.svg("temp_qr.svg", scale=5)
    subprocess.call(["open", "temp_qr.svg"])

    print "Hit enter to continue"
    raw_input()

    os.remove("temp_qr.svg")

if __name__ == "__main__":
    if sys.argv < 2:
        print "Usage: %s <username>"
        sys.exit(1)

    username = sys.argv[1]
    createNewUser(username)