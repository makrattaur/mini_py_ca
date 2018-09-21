#!/usr/bin/env python3

import argparse

from cryptography import x509

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from mini_py_ca import config
from mini_py_ca import common
from mini_py_ca import dbaccess
from mini_py_ca import utils


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--section",
        help = "Section name to use"
    )

    args = parser.parse_args()

    section = config.get_section_for_context("revocation_list", args.section)
    if not isinstance(section, config.RevocationList):
        raise Exception("Wrong section kind for generating revocation list.")

    utc_now = utils.utc_now()
    crl_start_time = utils.floor_time_minute(utc_now)
    crl_next_update = crl_start_time + section.duration

    revocation_list_contents = dbaccess.get_certificates_for_crl(utc_now)
    number = dbaccess.get_next_crl_number()

    authority_certificate_serial = dbaccess.find_current_authority_certificate_serial()
    authority_certificate = common.load_certificate_by_serial(authority_certificate_serial)
    private_key = common.load_private_key()
    public_key = private_key.public_key()

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(authority_certificate.issuer)
    builder = builder.last_update(crl_start_time)
    builder = builder.next_update(crl_next_update)

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
        critical = False
    )

    builder = builder.add_extension(
        x509.CRLNumber(number),
        critical = False
    )

    for cert in revocation_list_contents:
        revoked_cert_builder = x509.RevokedCertificateBuilder()

        revoked_cert_builder = revoked_cert_builder.serial_number(cert.serial)
        revoked_cert_builder = revoked_cert_builder.revocation_date(
            utils.floor_time_minute(cert.revocation_date)
        )

        if cert.revocation_reason != "unspecified":
            revoked_cert_builder = revoked_cert_builder.add_extension(
                x509.CRLReason(dbaccess.reason_flag_mapping[cert.revocation_reason]),
                critical = False
            )

        builder = builder.add_revoked_certificate(
            revoked_cert_builder.build(default_backend())
        )

    hash_algorithm = utils.hash_algorithm_name_to_instance(section.signature_algorithm)
    crl = builder.sign(
        private_key = private_key,
        algorithm = hash_algorithm,
        backend = default_backend()
    )

    common.write_crl_to_disk(crl)
    dbaccess.add_crl_to_db(crl, utc_now)

    msg_format_prefix = "Generated CRL number {0} "
    msg_format_suffix = ":\n - valid on {1}\n - next update expected on {2}"
    msg_format_empty = msg_format_prefix + "with no revoked certificates" + msg_format_suffix
    msg_format = msg_format_prefix + "with {3} revoked certificate(s)" + msg_format_suffix

    chosen_format = msg_format if len(revocation_list_contents) > 0 else msg_format_empty

    print(chosen_format.format(
        number,
        crl_start_time.astimezone(tz = None),
        crl_next_update.astimezone(tz = None),
        len(revocation_list_contents)
    ))


if __name__ == "__main__":
    main()


