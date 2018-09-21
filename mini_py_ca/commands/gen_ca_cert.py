#!/usr/bin/env python3

import argparse
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtensionOID

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from mini_py_ca import config
from mini_py_ca import common
from mini_py_ca import dbaccess
from mini_py_ca import x509ext
from mini_py_ca import utils

from pprint import pprint


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--section",
        help = "Section name to use"
    )

    args = parser.parse_args()

    section = config.get_section_for_context("root_authority", args.section)
    if not isinstance(section, config.Certificate):
        raise Exception("Wrong section kind for root certificate generation.")

    duration = section.duration
    hash_algorithm = utils.hash_algorithm_name_to_instance(section.signature_algorithm)

    current_time = utils.utc_now()
    not_before = utils.floor_time_minute(current_time)
    not_after = not_before + duration

    authority_private_key = common.load_private_key()
    authority_public_key = authority_private_key.public_key()

    serial_number = dbaccess.generate_certificate_serial()

    builder = x509.CertificateBuilder()

    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)
    builder = builder.serial_number(serial_number)

    issuer = utils.distinguished_name_to_x509_name(section.distinguished_name)
    builder = builder.subject_name(issuer)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(authority_public_key)

    ext_ctx = x509ext.ExtensionContext(
        authority_key = authority_public_key,
        subject_key = authority_public_key
    )

    builder = x509ext.add_extensions(
        builder,
        ext_ctx,
        extension_config_list = section.extensions,
        existing_extensions = []
    )

    certificate = builder.sign(
        private_key = authority_private_key,
        algorithm = hash_algorithm,
        backend = default_backend()
    )

    common.write_certificate_to_disk(certificate, is_self_signed = True)
    dbaccess.add_certificate_to_db(certificate, is_self_signed = True)

    msg_format = "Generated self-signed certificate with serial {0}:\n" + \
        " - valid on {1}\n" + \
        " - expiring on {2}"

    print(msg_format.format(
        utils.format_serial(certificate.serial_number),
        not_before.astimezone(tz = None),
        not_after.astimezone(tz = None)
    ))


if __name__ == "__main__":
    main()

