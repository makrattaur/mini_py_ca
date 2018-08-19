

import datetime
import sqlite3

from cryptography import x509

from mini_py_ca import common
from mini_py_ca import utils

database_connection = None

class IssuedCertificate:
    def __init__(self, issued_certificate_id, date_created, not_before_date, not_after_date, serial, subject, is_self_signed, is_revoked, revocation_date, revocation_reason):
        self.id = issued_certificate_id
        self.date_created = date_created
        self.not_before_date = not_before_date
        self.not_after_date = not_after_date
        self.serial = serial
        self.subject = subject
        self.is_self_signed = is_self_signed
        self.is_revoked = is_revoked
        self.revocation_date = revocation_date
        self.revocation_reason = revocation_reason

issued_certificate_create = """CREATE TABLE issued_certificate (
    issued_certificate_id INTEGER NOT NULL PRIMARY KEY,
    date_created INT NOT NULL,
    not_before_date INT NOT NULL,
    not_after_date INT NOT NULL,
    serial TEXT UNIQUE NOT NULL,
    subject TEXT NOT NULL,
    is_self_signed INT
);"""

revoked_certificate_create = """CREATE TABLE revoked_certificate (
    revoked_certificate_id INTEGER NOT NULL PRIMARY KEY,
    issued_certificate_id NOT NULL,
    revocation_date INT NOT NULL,
    reason TEXT NOT NULL,
    FOREIGN KEY (issued_certificate_id) REFERENCES issued_certificate(issued_certificate_id)
);"""

revocation_list_create = """CREATE TABLE revocation_list (
    revocation_list_id INTEGER NOT NULL PRIMARY KEY,
    date_created INT NOT NULL,
    update_date INT NOT NULL,
    next_update_date INT NOT NULL
);"""

reason_flag_mapping = {
    "unspecified": x509.ReasonFlags.unspecified,
    "keyCompromise": x509.ReasonFlags.key_compromise,
    "caCompromise": x509.ReasonFlags.ca_compromise,
    "affiliationChanged": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
#    "certificateHold": x509.ReasonFlags.certificate_hold,
    "privilegeWithdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aaCompromise": x509.ReasonFlags.aa_compromise,
#    "removeFromCRL": x509.ReasonFlags.remove_from_crl,
}

def generate_certificate_serial():
    conn = get_connection()

    attempt_count = 0
    while attempt_count < 10:
        serial = x509.random_serial_number()

        if not serial_exists(conn, serial):
            return serial

        attempt_count = attempt_count + 1

    raise Exception("Failed to get new random serial 10 times ?!")

def add_certificate_to_db(certificate, is_self_signed):
    conn = get_connection()

    now = datetime.datetime.now(tz = datetime.timezone.utc)
    utc_not_valid_before = utils.make_utc_datetime_aware(certificate.not_valid_before)
    utc_not_valid_after = utils.make_utc_datetime_aware(certificate.not_valid_after)
    values = {
        "date_created": utils.to_timestamp_milis(now),
        "not_before_date": utils.to_timestamp_milis(utc_not_valid_before),
        "not_after_date": utils.to_timestamp_milis(utc_not_valid_after),
        "serial": utils.format_serial(certificate.serial_number),
        "subject": utils.x509_name_to_ldap_string(certificate.subject),
        "is_self_signed": is_self_signed
    }

    insert_cur = conn.cursor()
    insert_cur.execute("""INSERT INTO issued_certificate (
    date_created,
    not_before_date,
    not_after_date,
    serial,
    subject,
    is_self_signed
) VALUES(
    :date_created,
    :not_before_date,
    :not_after_date,
    :serial,
    :subject,
    :is_self_signed
);""",
        values
    )

    conn.commit()
    insert_cur.close()

def find_current_authority_certificate_serial():
    conn = get_connection()

    cur = conn.cursor()
    with AutoClose(cur):
        cur.execute("""SELECT ic.serial
FROM issued_certificate AS ic
WHERE ic.issued_certificate_id = (SELECT MAX(issued_certificate_id)
	FROM issued_certificate AS ic_max
	WHERE ic_max.is_self_signed = 1
);""")

        return cur.fetchone()[0]

def serial_exists(conn, serial):
    check_cur = conn.cursor()

    with AutoClose(check_cur):
        check_cur.execute("""SELECT *
FROM issued_certificate AS ic
WHERE ic.serial = :serial;
""",
            {"serial": utils.format_serial(serial)}
        )
        
        return not check_cur.fetchone() is None

def get_certificate_by_id(certificate_id):
    conn = get_connection()

    array = get_certificates_by_filter(
        conn,
        "ic.issued_certificate_id = :certificate_id",
        {"certificate_id": certificate_id}
    )

    if len(array) < 1:
        return None

    return array[0]

def revoke_certificate_by_id(revocation_time, certificate_id, serial, reason = None):
    if reason is None:
        reason = "unspecified"

    values = {
        "issued_certificate_id": certificate_id,
        "reason": reason,
        "revocation_date": utils.to_timestamp_milis(revocation_time)
    }

    add_plaintext_revocation_entry(serial, revocation_time, reason)

    conn = get_connection()
    insert_cur = conn.cursor()
    insert_cur.execute("""INSERT INTO revoked_certificate (
    issued_certificate_id,
    revocation_date,
    reason
) VALUES(
    :issued_certificate_id,
    :revocation_date,
    :reason
);""",
        values
    )

    conn.commit()
    insert_cur.close()

def get_certificates_for_crl(time_ref):
    conn = get_connection()

    array = get_certificates_by_filter(
        conn,
        ":time_ref < ic.not_after_date AND rc.revoked_certificate_id IS NOT NULL",
        {"time_ref": utils.to_timestamp_milis(time_ref)}
    )

    return array

def get_next_crl_number():
    conn = get_connection()

    cur = conn.cursor()
    cur.execute("""SELECT MAX(rl.revocation_list_id)
FROM revocation_list AS rl;""")

    with AutoClose(cur):
        row = cur.fetchone()
        value = row[0]

        if value is None:
            return 1

        return value + 1

def add_crl_to_db(crl, date_created):
    conn = get_connection()

    number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    utc_next_update = utils.make_utc_datetime_aware(crl.next_update)
    utc_last_update = utils.make_utc_datetime_aware(crl.last_update)

    values = {
        "revocation_list_id": number,
        "date_created": utils.to_timestamp_milis(date_created),
        "update_date": utils.to_timestamp_milis(utc_last_update),
        "next_update_date": utils.to_timestamp_milis(utc_next_update),
    }

    cur = conn.cursor()
    cur.execute("""INSERT INTO revocation_list (
    revocation_list_id,
    date_created,
    update_date,
    next_update_date
) VALUES(
    :revocation_list_id,
    :date_created,
    :update_date,
    :next_update_date
);""",
        values
    )

    conn.commit()
    cur.close()

class AutoClose:

    def __init__(self, obj):
        self.obj = obj

    def __enter__(self):
        return self.obj

    def __exit__(self, exec_type, exec_value, traceback):
        self.obj.close()

def add_plaintext_revocation_entry(serial, time, reason):
    entry = [ \
       str(utils.to_timestamp_milis(time)), \
       serial, \
       reason \
    ]

    log_path = common.make_path_from_config_dir("revocation.log")
    with open(log_path, "a") as log:
        log.write((",".join(entry)) + "\n")

def get_certificates_by_filter(conn, sql_filter, values):
    cur = conn.cursor()

    full_query = """SELECT
    ic.issued_certificate_id,
    ic.date_created,
    ic.not_before_date,
    ic.not_after_date,
    ic.serial,
    ic.subject,
    ic.is_self_signed,
    rc.revoked_certificate_id,
    rc.revocation_date,
    rc.reason
FROM issued_certificate AS ic
LEFT JOIN revoked_certificate AS rc ON ic.issued_certificate_id = rc.issued_certificate_id
WHERE """ + sql_filter +  ";"

    with AutoClose(cur):
        cur.execute(full_query, values);

        results = []

        row = cur.fetchone()
        while not row is None:
            ic = IssuedCertificate(
                issued_certificate_id = row[0],
                date_created = utils.from_timestamp_milis(row[1]),
                not_before_date = utils.from_timestamp_milis(row[2]),
                not_after_date = utils.from_timestamp_milis(row[3]),
                serial = int(row[4], 16),
                subject = row[5],
                is_self_signed = row[6],
                is_revoked = not row[7] is None,
                revocation_date = None if row[8] is None else utils.from_timestamp_milis(row[8]),
                revocation_reason = row[9]
            )

            results.append(ic)
            row = cur.fetchone()

        return results

def get_connection():
    global database_connection

    if database_connection is None:
        db_path = common.make_path_from_config_dir("db.sqlite")
        database_connection = sqlite3.connect(db_path)
        
        pragma_cur = database_connection.execute("PRAGMA foreign_keys = ON;")
        pragma_cur.close()

        create_tables(database_connection)

    return database_connection

def create_table_if_not_exists(conn, name, create_statement):
    check_cur = conn.cursor()

    with AutoClose(check_cur):
        check_cur.execute("""SELECT *
FROM sqlite_master
WHERE type = 'table' AND name = :table_name;
""",
            {"table_name": name}
        )

        if not check_cur.fetchone() is None:
            return False

        create_cur = conn.execute(create_statement)
        conn.commit()
        create_cur.close()

        return True

def create_tables(conn):
    create_table_if_not_exists(conn, "issued_certificate", issued_certificate_create)
    create_table_if_not_exists(conn, "revoked_certificate", revoked_certificate_create)
    create_table_if_not_exists(conn, "revocation_list", revocation_list_create)


