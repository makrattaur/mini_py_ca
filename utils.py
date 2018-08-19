
import datetime
import re

from cryptography import x509
from cryptography.x509.oid import NameOID

from cryptography.hazmat.primitives import hashes

short_rdn_type_mapping = {
    "dc": NameOID.DOMAIN_COMPONENT,
    "c": NameOID.COUNTRY_NAME,
    "st": NameOID.STATE_OR_PROVINCE_NAME,
    "l": NameOID.LOCALITY_NAME,
    "o": NameOID.ORGANIZATION_NAME,
    "ou": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "cn": NameOID.COMMON_NAME,
    "e": NameOID.EMAIL_ADDRESS
}

reverse_short_rdn_type_mapping = dict()
for k, v in short_rdn_type_mapping.items():
    reverse_short_rdn_type_mapping[v.dotted_string] = k

unix_epoch = datetime.datetime(1970, 1, 1, tzinfo = datetime.timezone.utc)

def write_all_bytes(filename, bytes):
    with open(filename, "wb") as file:
        file.write(bytes)

def read_all_bytes(filename):
    with open(filename, "rb") as file:
            return file.read()

def distinguished_name_to_x509_name(dn):
    name_list = []

    for rdn in dn:
        rdn_type = rdn[0].lower()
        value = rdn[1]

        if rdn_type in short_rdn_type_mapping:
            name_list.append(x509.NameAttribute(short_rdn_type_mapping[rdn_type], value))
        else:
            name_list.append(x509.NameAttribute(rdn_type, value))

    return x509.Name(name_list)

def hash_algorithm_name_to_instance(name):
    if name == "sha256":
        return hashes.SHA256()
    elif name == "sha512":
        return hashes.SHA512()

def floor_time_second(value):
    return value - datetime.timedelta(
        microseconds = value.microsecond
    )

def floor_time_second_interval(value, interval):
    return value - datetime.timedelta(
        seconds = value.seconds % interval,
        microseconds = value.microsecond
    )

def floor_time_minute(value):
    return value - datetime.timedelta(
        seconds = value.second,
        microseconds = value.microsecond
    )

def make_utc_datetime_aware(value):
    return value.replace(tzinfo = datetime.timezone.utc)

def to_timestamp_milis(value):
    return round((value - unix_epoch) / datetime.timedelta(milliseconds = 1))

def from_timestamp_milis(value):
    return unix_epoch + datetime.timedelta(milliseconds = value)

def x509_name_to_ldap_string(name):

    elements = []

    for rdn in reversed(list(name)):
        
        type_string = None
        if rdn.oid.dotted_string in reverse_short_rdn_type_mapping:
            type_string = reverse_short_rdn_type_mapping[rdn.oid.dotted_string].upper()
        else:
            type_string = rdn.oid.dotted_string

        elements.append(type_string + "=" + rdn.value)

    return ",".join(elements)

def format_serial(serial):
    return "{0:040x}".format(serial)

def utc_now():
    return datetime.datetime.now(tz = datetime.timezone.utc)

