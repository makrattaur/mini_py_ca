
import ipaddress
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtensionOID

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from mini_py_ca import config
from mini_py_ca import utils

def add_extensions(builder, context, extension_config_list, existing_extensions):
    remaining_configs = None

    if len(existing_extensions) > 0:
        ext_config_map = dict()

        for config_ext in extension_config_list:
            ext_config_map[extension_oid_mapping[config_ext.name]] = config_ext

        for ext in existing_extensions:
            if not ext.value.oid in ext_config_map:
                builder = builder.add_extension(ext.value, ext.critical)

                continue

            ext_config = ext_config_map[ext.value.oid]
            del ext_config_map[ext.value.oid]

            if ext_config.action == config.ExtensionAction.ADD:
                builder = builder.add_extension(ext.value, ext.critical)

            elif ext_config.action == config.ExtensionAction.REPLACE:
                ext_override = extension_handlers[ext_config.name](context, ext_config)
                builder = builder.add_extension(ext_override, ext_config.critical)

            elif ext_config.action is None and not ext_config.forced_critical_value is None:
                builder = builder.add_extension(ext.value, ext_config.forced_critical_value)

        remaining_configs = ext_config_map.values()
    else:
        remaining_configs = extension_config_list

    for ext_config in remaining_configs:
        if ext_config.action is None:
            continue

        ext = extension_handlers[ext_config.name](context, ext_config)
        critical = False
    
        if ext_config.action == config.ExtensionAction.REPLACE:
            critical = ext_config.critical
        elif ext_config.action == config.ExtensionAction.ADD:
            if not ext_config.critical is None:
                critical = ext_config.critical
            else:
                critical = ext_config.forced_critical_value

        builder = builder.add_extension(ext, critical)

    return builder

class ExtensionContext:
    def __init__(self, authority_key, subject_key):
        self.authority_key = authority_key
        self.subject_key = subject_key

def parse_general_name(general_name):
    if len(general_name) > 1:
        raise Exception("One GeneralName must be specified at a time.")
    
    name_tuple = list(general_name.items())[0]
    name_type = name_tuple[0].lower()
    name_value = name_tuple[1]

    if name_type == "uri":
        return x509.UniformResourceIdentifier(name_value)
    elif name_type == "ip":
        return x509.IPAddress(ipaddress.ip_address(name_value))
    elif name_type == "dns":
        return x509.DNSName(name_value)
    elif name_type == "email":
        return x509.RFC822Name(name_value)
    else:
        raise Exception("Unknown GeneralName type '" + name_type + "'.")

usage_name_mapping = {
    "digitalSignature": "digital_signature",
    "nonRepudiation": "content_commitment",
    "keyEncipherment": "key_encipherment",
    "dataEncipherment": "data_encipherment",
    "keyAgreement": "key_agreement",
    "keyCertSign": "key_cert_sign",
    "cRLSign": "crl_sign",
    "encipherOnly": "encipher_only",
    "decipherOnly": "decipher_only",
}

def handle_key_usage(ctx, ext):
    usages = {
        "digital_signature": False,
        "content_commitment": False,
        "key_encipherment": False,
        "data_encipherment": False,
        "key_agreement": False,
        "key_cert_sign": False,
        "crl_sign": False,
        "encipher_only": False,
        "decipher_only": False
    }

    for usage in ext.dict["usages"]:
        if not usage in usage_name_mapping:
            raise Exception("Invalid usage '" + usage + "'.")

        usages[usage_name_mapping[usage]] = True

    return x509.KeyUsage(**usages)

def handle_basic_constraints(ctx, ext):
    is_ca = ext.dict["ca"]

    path_length = None
    if "pathLenConstraint" in ext.dict:
        path_length = ext.dict["pathLenConstraint"]

    return x509.BasicConstraints(ca = is_ca, path_length = path_length)

def handle_subject_key_identifier(ctx, ext):
    
    if not "value" in ext.dict:
        raise Exception("No value to give to the extension.")

    if ext.dict["value"] != "subject_hash":
        raise Exception("The only value supported is 'subject_hash'")

    return x509.SubjectKeyIdentifier.from_public_key(ctx.subject_key)

def handle_authority_key_identifier(ctx, ext):
    
    if not "keyIdentifier" in ext.dict:
        raise Exception("No value to give to the extension.")

    if ext.dict["keyIdentifier"] != "issuer_hash":
        raise Exception("The only value supported is 'issuer_hash'.")

    if "authorityCertIssuer" in ext.dict or "authorityCertSerialNumber" in ext.dict:
        raise Exception("Certificate-based authority identifier not supported.")

    return x509.AuthorityKeyIdentifier.from_issuer_public_key(ctx.authority_key)

def handle_crl_distribution_points(ctx, ext):

    distribution_points = []
    for point in ext.dict["distributionPoints"]:
        if len(point) > 1:
            raise Exception("One distribution point must be specified per array element.")

        if not "fullName" in point:
            raise Exception("Only GeneralName-based distribution points are supported.")

        general_names = []
        for general_name in point["fullName"]:
            general_names.append(parse_general_name(general_name))

        distribution_points.append(x509.DistributionPoint(
            full_name = general_names,
            relative_name = None,
            reasons = None,
            crl_issuer = None
        ))

    return x509.CRLDistributionPoints(distribution_points)

def handle_authority_access_info(ctx, ext):

    descriptions = []
    for desc in ext.dict["accessDescriptions"]:
        if len(desc) > 1:
            raise Exception("One authority info access description must be specified at a time.")

        desc_tuple = list(desc.items())[0]
        method = desc_tuple[0]
        location = desc_tuple[1]

        method_oid = None
        if method == "caIssuers":
            method_oid = x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
        elif method == "ocsp":
            method_oid = x509.oid.AuthorityInformationAccessOID.OCSP
        else:
            raise Exception("Invalid authority access description method '" + method + "'.")

        parsed_location = parse_general_name(location)
        descriptions.append(x509.AccessDescription(method_oid, parsed_location))

    return x509.AuthorityInformationAccess(descriptions)

extension_handlers = {
    "keyUsage": handle_key_usage,
    "basicConstraints": handle_basic_constraints,
    "subjectKeyIdentifier": handle_subject_key_identifier,
    "authorityKeyIdentifier": handle_authority_key_identifier,
    "crlDistributionPoints": handle_crl_distribution_points,
    "authorityInfoAccess": handle_authority_access_info
}

extension_oid_mapping = {
    "keyUsage": ExtensionOID.KEY_USAGE,
    "basicConstraints": ExtensionOID.BASIC_CONSTRAINTS,
    "subjectKeyIdentifier": ExtensionOID.SUBJECT_KEY_IDENTIFIER,
    "authorityKeyIdentifier": ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
    "crlDistributionPoints": ExtensionOID.CRL_DISTRIBUTION_POINTS,
    "authorityInfoAccess": ExtensionOID.AUTHORITY_INFORMATION_ACCESS
}



