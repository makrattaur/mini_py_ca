#!/usr/bin/env python3


import argparse
import getpass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from mini_py_ca import utils
from mini_py_ca import config


parser = argparse.ArgumentParser()
parser.add_argument(
    '--encrypt',
    action='store_true',
    help='Encrypt the generated key'
)

args = parser.parse_args()

section = config.get_section_for_context("authority_key")
if not isinstance(section, config.KeySpec):
    raise Exception("Wrong section kind for asymmetric key generation.")

key_size = section.key_length

private_key = rsa.generate_private_key(
    public_exponent = 65537,
    key_size = key_size,
    backend = default_backend()
)

key_encryption = serialization.NoEncryption()
if args.encrypt:
    password = getpass.getpass(prompt = "Key password: ")
    key_encryption = serialization.BestAvailableEncryption(password.encode())

serialized_private_key = private_key.private_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PrivateFormat.PKCS8,
    encryption_algorithm = key_encryption
)

utils.write_all_bytes("private/cakey.pem", serialized_private_key)

public_key = private_key.public_key()
serialized_public_key = public_key.public_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PublicFormat.SubjectPublicKeyInfo
)

utils.write_all_bytes("public_key.pem", serialized_public_key)


