#!/usr/bin/env python3


import argparse
import getpass
import os
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from mini_py_ca import common
from mini_py_ca import utils


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'operation',
        choices = [ "encrypt", "decrypt" ],
        help = 'The operation on the key'
    )

    args = parser.parse_args()

    private_key_path = common.get_current_private_key_path()
    private_key_bytes = utils.read_all_bytes(private_key_path)

    private_key = None
    is_encrypted = False
    try:
        private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password = None,
            backend = default_backend()
        )
    except TypeError:
        private_key = load_encrypted_private_key(private_key_bytes)
        is_encrypted = True

    if args.operation == "decrypt" and not is_encrypted:
        print("Key is already decrypted.")
        sys.exit(1)

    key_encryption = serialization.NoEncryption()
    if args.operation == "encrypt":
        password = getpass.getpass(prompt = "New key password: ")
        key_encryption = serialization.BestAvailableEncryption(password.encode())


    serialized_private_key = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.PKCS8,
        encryption_algorithm = key_encryption
    )

    temp_private_key_path = common.get_temp_private_key_path()
    utils.write_all_bytes(temp_private_key_path, serialized_private_key)
    os.replace(temp_private_key_path, private_key_path)

    print("Key " + args.operation + "ed successfully.")


if __name__ == "__main__":
    main()

