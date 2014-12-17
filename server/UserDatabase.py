import os
from server.Configuration import CERTIFICATE_DIRECTORY
from shared.Certificate import Certificate

__author__ = 'iravid'

_database = {}
_initialized = False

_servPrivKey = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAr0pefsJpu51oWwVWeTtoMYT9OkMkyLKBiO7N2Fi0QiJEQAC8\ndBh5A51B8VxHjKjHIDgapIiH3ZYddlJwGy3Lh0vax8EJKhh4XtaTWPzpu0VbCqD7\nShkC9DDKHw/Ipogl2lhz380zdJTyAvsT6UcXk1Hgs4yyAxKnmcVlQXgvY9I+4gok\nHDhSjZD276SDmL3WoqaXQQkg8zqbZHsEZzVkh8irgF3IzACj8MY38DJwk5mD9FCp\nK0KPDA2h+7AaltO75F4v9lgKRNRXGTB3COQ+N8v1RrQDV/+v5B0C/BY2cHZfCkOT\nQtaqxn1wzb32DjdpNISrwVmgieYCVJpCIWB4lQIDAQABAoIBAQCrJmzvTXmZMw7y\nWFrfUe7g8t2hJm/i+c/aWHhp9epC7FxBNbbLkB2QNtptBFHj9+M9BSqWXaxy4aBw\np/tHvkYMGzdJdKQzEuNsjgwehgrcy9IhpZ7V8Wfd70laXLnoR+TVtSmmaiAEg21t\nFaOSUNSnBfnktcoVkABO9tpvux5iUgLFpMpFJWDtySlPiqM8FsSDe6xGv/njh2iQ\nJloiA0RGE4+Q+8V+cmVBbcBUFwLdEnvd/JXziq51oCgVoe5BS5MTaQmiBY+7zgzO\nlFooR4f78XOJGPCzkaV3TvK2lBQE4lN6z0KXJyc0L2Hg504p9G2NUvmx57nGfKqW\nTxN0K7qBAoGBALZ58kJXaNoZ1EUv7zFdqEZW10Ku+liScsfqsopizazcweg5VcYE\nv59J5EZCPew5N7BWai9FT3IIM4z813gaj4z9HX9ovtX1HU5uAOUCn7K7PQvY9zYN\nVAENlwpvyhxSWXHweZ+DpC+tZ6EqkhRM9T0oDFCCS8qnRO7FEwwpG4l1AoGBAPXr\nN7MhCByo37U9GBM4l3/kbm4/z4Nnd/Gonpeg+4J8TZSVUL3PQoHzO0/47DQptl6R\nGaxXp5iqxSXHewwM98fVa9ImkWZk/983DaApDxk/wAOsy2CSKmBon25h1rxHFCKd\nB0oBCJWPqcnLlOVIULl7ZSUiK+DAEtDPLSwbbC6hAoGAXuU4KWwPqSy5iWmOONv+\nAOZ0d8dLhfhTHMhfJTyQvY7ogH4gryQVCx+ASVF1pn1zCo9GFWM0F5dQR8fNvjYB\n5U5Uose0Rsx7+yeV64LbzjU1YA3rMf7oasvIerL8JpJk1a47ccsh/XFubRAYe9ox\nxyYmkU/RXohyfsGaUD6ohWkCgYEA4qOgFs93eWpNmeuvN2+teCmfeK4IYlNGYIoF\ndzre8Lf8i9Y8rmHIKplu7Vo83iofL/JMFeBGzlV8EkBQ75838IyJrQjscdDdW+uR\n/Cw7BQsSvJBQczTiJy3k2UcEL0rWjLvpjtN7BNN9KEQeelz2QKsvYVSn2Z9K9/Qn\n7oFrZ2ECgYBqvY1nAZ1GaRAT5k1dDfji+bOBmnZ77SAtoCAjuIn4YN3gsApSxTbY\nLGfJQ9ydeS/ScJDhcdzz+kdwLNHy4CNyvMJtCgZ+v7aidN1Ucp9Lwr8+2wyq98lP\nebA5G25WyGd61JzF5ae8+HfsoxPnmryeMhBycBIiNBGG3fA/w4qTRw==\n-----END RSA PRIVATE KEY-----'
_servPubKey = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr0pefsJpu51oWwVWeTto\nMYT9OkMkyLKBiO7N2Fi0QiJEQAC8dBh5A51B8VxHjKjHIDgapIiH3ZYddlJwGy3L\nh0vax8EJKhh4XtaTWPzpu0VbCqD7ShkC9DDKHw/Ipogl2lhz380zdJTyAvsT6UcX\nk1Hgs4yyAxKnmcVlQXgvY9I+4gokHDhSjZD276SDmL3WoqaXQQkg8zqbZHsEZzVk\nh8irgF3IzACj8MY38DJwk5mD9FCpK0KPDA2h+7AaltO75F4v9lgKRNRXGTB3COQ+\nN8v1RrQDV/+v5B0C/BY2cHZfCkOTQtaqxn1wzb32DjdpNISrwVmgieYCVJpCIWB4\nlQIDAQAB\n-----END PUBLIC KEY-----'

def getByUserId(userId):
    return _database.get(userId, None)

def addCertificate(cert):
    _database[cert.userId] = cert

def _initialize():
    global _initialized
    if _initialized:
        return

    def walkFunc(arg, dirname, fnames):
        for fname in fnames:
            if not fname.endswith("cert"):
                continue

            cert = Certificate.deserialize(open(os.path.join(dirname, fname), "rb").read())
            addCertificate(cert)

    os.path.walk(CERTIFICATE_DIRECTORY, walkFunc, None)
    _initialized = True

_initialize()



