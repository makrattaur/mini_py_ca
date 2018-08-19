#!/usr/bin/env python3

import argparse
import datetime
import re
import sys

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


parser = argparse.ArgumentParser()
parser.add_argument(
    "--section",
    help = "Section name to use"
)

parser.add_argument(
    'csr_file',
    help = 'The CSR to sign'
)

args = parser.parse_args()

section = config.get_section_for_context("sign_request", args.section)
if not isinstance(section, config.SignRequest):
    raise Exception("Wrong section kind for signing certificate request.")

authority_certificate_serial = dbaccess.find_current_authority_certificate_serial()
authority_certificate = common.load_certificate_by_serial(authority_certificate_serial)

request_bytes = utils.read_all_bytes(args.csr_file)
request = x509.load_pem_x509_csr(request_bytes, default_backend())

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

builder = builder.subject_name(request.subject)
builder = builder.issuer_name(authority_certificate.issuer)
builder = builder.public_key(request.public_key())

ext_ctx = x509ext.ExtensionContext(
    authority_key = authority_public_key,
    subject_key = authority_public_key
)

builder = x509ext.add_extensions(
    builder,
    ext_ctx,
    extension_config_list = section.extensions,
    existing_extensions = request.extensions
)

certificate = builder.sign(
    private_key = authority_private_key,
    algorithm = hash_algorithm,
    backend = default_backend()
)

common.write_certificate_to_disk(certificate, is_self_signed = False)
dbaccess.add_certificate_to_db(certificate, is_self_signed = False)

msg_format = "Generated certificate with serial {0}:\n" + \
    " - valid on {1}\n" + \
    " - expiring on {2}\n" + \
    " - for subject {3}"

print(msg_format.format(
    utils.format_serial(certificate.serial_number),
    not_before.astimezone(tz = None),
    not_after.astimezone(tz = None),
    utils.x509_name_to_ldap_string(certificate.subject)
))


