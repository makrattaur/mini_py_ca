
import datetime
import re
import os
import shutil
import getpass
import sys

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtensionOID

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from mini_py_ca import config
from mini_py_ca import x509ext
from mini_py_ca import utils


cert_ext = ".crt"
date_format = "{0.year:4d}-{0.month:02d}-{0.day:02d}_{0.hour:02d}h{0.minute:02d}"


def write_certificate_to_disk(certificate, is_self_signed):
    if not os.path.exists("byserial"):
        os.mkdir("byserial")

    target_dir = "cacert" if is_self_signed else "cert"
    if not os.path.exists(target_dir):
        os.mkdir(target_dir)

    serialized_certificate = certificate.public_bytes(
        encoding = serialization.Encoding.PEM,
    )

    full_serial = utils.format_serial(certificate.serial_number)
    short_serial = full_serial[:8]

    byserial_path = os.path.join("byserial", full_serial + cert_ext)
    utils.write_all_bytes(byserial_path, serialized_certificate)

    common_name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    safe_common_name = re.sub(r"[^a-zA-Z0-9-_]", "_", common_name)

    utc_not_valid_before = utils.make_utc_datetime_aware(certificate.not_valid_before)

    symlink_name_format = None
    if is_self_signed:
        symlink_name_format = date_format + "_{1}" + cert_ext
    else:
        symlink_name_format = "{2}_" + date_format + "_{1}" + cert_ext

    symlink_name = symlink_name_format.format(
        utc_not_valid_before.astimezone(tz = None),
        short_serial,
        safe_common_name
    )

    symlink_path = os.path.join(target_dir, symlink_name)

    full_src = os.path.abspath(byserial_path)
    full_dst = os.path.abspath(symlink_path)
    if os.name == "nt":
        shutil.copyfile(full_src, full_dst)
    else:
        os.symlink(full_src, full_dst)

def write_crl_to_disk(crl):
    if not os.path.exists("crl"):
        os.mkdir("crl")

    serialized_crl = crl.public_bytes(
        encoding = serialization.Encoding.PEM,
    )

    utc_next_update = utils.make_utc_datetime_aware(crl.next_update)
    number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number

    crl_format = "{1:04d}_" + date_format + ".crl"
    crl_filename = crl_format.format(
        utc_next_update.astimezone(tz = None),
        number
    )

    crl_path = os.path.join("crl", crl_filename) 
    utils.write_all_bytes(crl_path, serialized_crl)

def load_certificate_by_serial(serial):
    certificate_bytes = utils.read_all_bytes("byserial/" + serial + cert_ext)

    return x509.load_pem_x509_certificate(certificate_bytes, default_backend())


def load_private_key():
    private_key_bytes = utils.read_all_bytes(get_current_private_key_path())

    try:
        private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password = None,
            backend = default_backend()
        )

        return private_key
    except TypeError:
        return load_encrypted_private_key_bytes(private_key_bytes)

def load_encrypted_private_key_bytes(private_key_bytes):
    try:
        password = getpass.getpass(prompt = "Key password: ")

        private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password = password.encode(),
            backend = default_backend()
        )

        return private_key
    except ValueError:
        print("Invalid key password.")
        sys.exit(1)

def make_path_from_config_dir(relative_path):
    dir_name = ".minipyca"

    if not os.path.exists(dir_name):
        os.mkdir(dir_name)

    return os.path.abspath(os.path.join(dir_name, relative_path))

def make_path_from_private_dir(relative_path):
    private_key_dir = make_path_from_config_dir("private")

    if not os.path.exists(private_key_dir):
        os.mkdir(private_key_dir)

    return os.path.join(private_key_dir, relative_path)

def get_current_private_key_path():
    return make_path_from_private_dir("cakey.pem")

def get_temp_private_key_path():
    return make_path_from_private_dir("cakey.pem.new")


