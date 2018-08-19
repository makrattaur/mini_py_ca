

from ruamel.yaml import YAML

import datetime
import re
import enum
from enum import Enum

from mini_py_ca import utils

supported_signature_algorithms = [ "sha256", "sha512" ]

class Certificate:
    def __init__(self, section_dict, section_name):
        parse_signed_object(self, section_dict, section_name)

        if not "distinguished_name" in section_dict:
            raise Exception("Missing certificate distinguished name in section '" + section_name + "'.")

        self.distinguished_name = parse_distinguished_name(section_dict["distinguished_name"])

class SignRequest:
    def __init__(self, section_dict, section_name):
        parse_signed_object(self, section_dict, section_name)

class RevocationList:
    def __init__(self, section_dict, section_name):
        parse_signed_object(self, section_dict, section_name)

class ExtensionAction(Enum):
    ADD = enum.auto
    REPLACE = enum.auto

class Extension:
    def __init__(self, ext_dict, ext_name):
        has_action = "action" in ext_dict
        has_critical_value = "critical" in ext_dict
        has_forced_critical_value = "forced_critical_value" in ext_dict

        if has_action:
            action = ext_dict["action"]

            if action == "add":
                if not has_critical_value and not has_forced_critical_value:
                    raise Exception("Atleast one criticality attribute must be given when adding an extension.")

                self.action = ExtensionAction.ADD
            elif action == "replace":
                if not has_critical_value:
                    raise Exception("Criticality attribute must be given when replacing an extension.")

                if has_forced_critical_value:
                    raise Exception("Cannot force criticality value when replacing an extension.")

                self.action = ExtensionAction.REPLACE
            else:
                raise Exception("Unknown action on extension.")
        else:
            if not has_forced_critical_value:
                self.action = ExtensionAction.ADD
            else:
                self.action = None

        self.critical = ext_dict["critical"] if has_critical_value else None
        self.forced_critical_value = ext_dict["forced_critical_value"] if has_forced_critical_value else None
        self.dict = ext_dict
        self.name = ext_name


def parse_signed_object(self, section_dict, section_name):
    if not "signature_algorithm" in section_dict:
        raise Exception("Missing signature algorithm in section '" + section_name + "'.")

    signature_algorithm = section_dict["signature_algorithm"].lower()
    if not signature_algorithm in supported_signature_algorithms:
        raise Exception("Invalid signature algorithm.")

    self.signature_algorithm = signature_algorithm

    if not "duration" in section_dict:
        raise Exception("Missing duration in section '" + section_name + "'.")

    self.duration = parse_duration(section_dict["duration"])

    self.extensions = []
    if "extensions" in section_dict:
        for key, value in section_dict["extensions"].items():
           self.extensions.append(Extension(value, key))

    self.section_name = section_name

def parse_duration(value_dict):
    if len(value_dict) > 1:
        raise Exception("Too many items in time length spec.")

    duration_tuple = list(value_dict.items())[0]
    time_unit = duration_tuple[0]
    value = duration_tuple[1]

    if time_unit == "years":
        return datetime.timedelta(days = 365 * value)
    elif time_unit == "days":
        return datetime.timedelta(days = value)
    elif time_unit == "hours":
        return datetime.timedelta(hours = value)
    elif time_unit == "minutes":
        return datetime.timedelta(minutes = value)
    elif time_unit == "hours":
        return datetime.timedelta(hours = value)
    elif time_unit == "seconds":
        return datetime.timedelta(seconds = value)
    elif time_unit == "weeks":
        return datetime.timedelta(weeks = value)
    else:
        raise Exception("Unknown unit '" + time_unit + "'.")

def parse_distinguished_name(rdn_sequence):
    dn = []

    for rdn_dict in rdn_sequence:
        if len(rdn_dict) > 1:
            raise Exception("Multi-valued RDN not supported.")

        rdn = list(rdn_dict.items())[0]

        if not re.fullmatch(r"(c|l|st|o|ou|cn|dc|e|[0-9.]+)", rdn[0]):
            raise Exception("Invalid RDN type '" + rdn[0] + "'.")

        dn.append(rdn)

    return dn

def read_config_file():
    parser = YAML(typ = "safe")

    return parser.load(utils.read_all_bytes("config.yml"))

def parse_section(section_dict, section_name):

    if not "kind" in section_dict:
        raise Exception("No section kind in section '" + section_name + "'.")

    kind = section_dict["kind"]

    if kind == "certificate":
        return Certificate(section_dict, section_name)
    elif kind == "sign_request":
        return SignRequest(section_dict, section_name)
    elif kind == "revocation_list":
        return RevocationList(section_dict, section_name)

def get_section_for_context(context_name, override_section_name = None):
    config = read_config_file()

    section_name = override_section_name
    if section_name is None:
        section_name = context_name

        if "_default_section" in config:
            default_section = config["_default_section"]

            if context_name in default_section:
                section_name = default_section[context_name]

    if not section_name in config:
        raise Exception("No section with name '" + section_name + "'.")

    return parse_section(config[section_name], section_name)

