#!/usr/bin/env python3


import sys

from mini_py_ca import dbaccess
from mini_py_ca import utils

certificate_id = int(sys.argv[1])
reason = None
if len(sys.argv) > 2:
    reason = sys.argv[2]

    if not reason in dbaccess.reason_flag_mapping:
        print("Invalid reason '{0}', must be one of {1}.".format(
            reason,
            ", ".join(key for key in dbaccess.reason_flag_mapping.keys())
        ))

        sys.exit(1)

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

print("Will revoke certificate id {0}, serial {1}, expiring on {2}, issued to {3}.".format(
    cert.id,
    formatted_serial,
    cert.not_after_date.astimezone(tz = None),
    cert.subject
))
dbaccess.revoke_certificate_by_id(utc_now, certificate_id, formatted_serial, reason)



