#!/usr/bin/env python3


import shutil

from mini_py_ca import dbaccess
from mini_py_ca import utils


def format_serial_for_display(serial):
    full_string = utils.format_serial(serial)
    
    return full_string[:6] + "..." + full_string[-6:]
    

cert_list = dbaccess.get_active_certificates()

terminal_size = shutil.get_terminal_size()

header_format_string = "{0:>4} | {1:15} | {2:26} | {3:26} | {4:2} | {5:2} | {6}"
print(header_format_string.format(
    "Id",
    "Serial",
    "Valid on",
    "Expires on",
    "S",
    "R",
    "Subject"
))
print("-" * terminal_size.columns)

cert_format_string = "{0.id:4d} | {1:15} | {2:26} | {3:26} | {4:2} | {5:2} | {0.subject}"
is_first_cert = True
for cert in cert_list:
    if not is_first_cert:
        print("-" * terminal_size.columns)
    else:
        is_first_cert = False

    print(cert_format_string.format(
        cert,
        format_serial_for_display(cert.serial),
        str(cert.not_after_date.astimezone(tz = None)),
        str(cert.not_before_date.astimezone(tz = None)),
        "Y" if cert.is_self_signed else "N",
        "Y" if cert.is_revoked else "N"
    ))

