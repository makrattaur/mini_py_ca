#!/usr/bin/env python3


import argparse
import sys

from mini_py_ca import dbaccess
from mini_py_ca import utils


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--reason",
        choices = [ key for key in dbaccess.reason_flag_mapping.keys() ],
        help = "The (optional) reason for the revocation"
    )

    parser.add_argument(
        'certificate_id',
        type = int,
        help = 'The certificate id to revoke'
    )

    args = parser.parse_args()

    certificate_id = args.certificate_id
    reason = args.reason

    cert = dbaccess.get_certificate_by_id(certificate_id)
    if cert is None:
        print("Cannot find certificate with id {0}.".format(cert.id))
        sys.exit(1)

    if cert.is_self_signed:
        print("Cannot revoke self-signed certificate id {0}.".format(cert.id))
        sys.exit(1)
        

    if cert.is_revoked:
        print("Certificate id {0} is already revoked.".format(cert.id))
        sys.exit(1)

    utc_now = utils.utc_now()
    if utc_now > cert.not_after_date:
        print("Certificate id {0} is already expired.".format(cert.id))
        sys.exit(1)

    formatted_serial = utils.format_serial(cert.serial)

    msg_format = "Will revoke certificate id {0}:\n" + \
        " - serial {1}\n" + \
        " - for subject {3}\n" + \
        " - issued on {4}\n" + \
        " - expiring on {2}"

    print(msg_format.format(
        cert.id,
        formatted_serial,
        cert.not_after_date.astimezone(tz = None),
        cert.subject,
        cert.not_before_date.astimezone(tz = None)
    ))
    dbaccess.revoke_certificate_by_id(utc_now, certificate_id, formatted_serial, reason)


if __name__ == "__main__":
    main()

