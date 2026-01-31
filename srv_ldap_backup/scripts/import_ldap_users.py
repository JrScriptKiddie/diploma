#!/usr/bin/env python3
import argparse
import base64
import csv
import hashlib
import io
import os
import subprocess
import sys
import tempfile


RUS_DEPT = "\u041a\u043e\u043c\u0430\u043d\u0434\u0430 (\u043e\u0442\u0434\u0435\u043b)"
RUS_LAST = "\u0424\u0430\u043c\u0438\u043b\u0438\u044f"
RUS_FIRST = "\u0418\u043c\u044f"


def normalize_header(value):
    return " ".join(value.strip().lower().split())


def decode_csv(path):
    raw = open(path, "rb").read()
    for enc in ("utf-8-sig", "cp1251", "utf-8", "latin1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def run_cmd(args, input_text=None, check=True):
    proc = subprocess.run(
        args,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and proc.returncode != 0:
        msg = "Command failed: {}\nstdout:\n{}\nstderr:\n{}".format(
            " ".join(args), proc.stdout, proc.stderr
        )
        raise RuntimeError(msg)
    return proc


def format_ldif_line(attr, value):
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    needs_b64 = False
    if value == "":
        needs_b64 = False
    else:
        if value[0] in (" ", ":", "<") or value.endswith(" "):
            needs_b64 = True
        if "\n" in value or "\r" in value or "\t" in value:
            needs_b64 = True
        for ch in value:
            if ord(ch) < 0x20 or ord(ch) > 0x7E:
                needs_b64 = True
                break
    if needs_b64:
        b64 = base64.b64encode(value.encode("utf-8")).decode("ascii")
        return "{}:: {}".format(attr, b64)
    return "{}: {}".format(attr, value)


def ldap_base_args(uri, bind_dn, bind_password):
    return ["-x", "-H", uri, "-D", bind_dn, "-w", bind_password]


def get_existing_uids(uri, bind_dn, bind_password, base_dn):
    args = ["ldapsearch"] + ldap_base_args(uri, bind_dn, bind_password) + [
        "-LLL",
        "-o",
        "ldif-wrap=no",
        "-b",
        base_dn,
        "(objectClass=posixAccount)",
        "uid",
        "uidNumber",
    ]
    proc = run_cmd(args, check=False)
    existing = set()
    uid_dns = {}
    max_uid = 0
    current_dn = None
    for line in proc.stdout.splitlines():
        if line.startswith("dn: "):
            current_dn = line.split("dn: ", 1)[1].strip()
        elif line.startswith("dn:: "):
            b64 = line.split("dn:: ", 1)[1].strip()
            try:
                current_dn = base64.b64decode(b64).decode("utf-8")
            except Exception:
                current_dn = None
        elif line.startswith("uid: "):
            uid = line.split("uid: ", 1)[1].strip()
            existing.add(uid)
            if current_dn and uid not in uid_dns:
                uid_dns[uid] = current_dn
        elif line.startswith("uidNumber: "):
            try:
                num = int(line.split("uidNumber: ", 1)[1].strip())
                if num > max_uid:
                    max_uid = num
            except ValueError:
                pass
    return existing, max_uid, uid_dns


def print_table(rows, columns):
    if not rows:
        return
    widths = []
    for key, label in columns:
        max_len = len(label)
        for row in rows:
            val = str(row.get(key, ""))
            if len(val) > max_len:
                max_len = len(val)
        widths.append(max_len)
    header = " | ".join(label.ljust(widths[i]) for i, (_, label) in enumerate(columns))
    sep = "-+-".join("-" * widths[i] for i in range(len(columns)))
    print(header)
    print(sep)
    for row in rows:
        line = " | ".join(
            str(row.get(key, "")).ljust(widths[i]) for i, (key, _) in enumerate(columns)
        )
        print(line)


def ensure_ou(uri, bind_dn, bind_password, ou_dn, ou_value):
    args = ["ldapsearch"] + ldap_base_args(uri, bind_dn, bind_password) + [
        "-LLL",
        "-b",
        ou_dn,
        "-s",
        "base",
        "(objectClass=organizationalUnit)",
        "dn",
    ]
    proc = run_cmd(args, check=False)
    if "dn:" in proc.stdout or "dn::" in proc.stdout:
        return
    lines = [
        format_ldif_line("dn", ou_dn),
        "objectClass: top",
        "objectClass: organizationalUnit",
        format_ldif_line("ou", ou_value),
        "",
    ]
    ldif = "\n".join([line for line in lines if line is not None])
    run_cmd(["ldapadd"] + ldap_base_args(uri, bind_dn, bind_password) + ["-c"], ldif)


def parse_dns(text):
    lines = []
    for line in text.splitlines():
        if line.startswith(" "):
            if lines:
                lines[-1] += line[1:]
        else:
            lines.append(line)
    dns = []
    for line in lines:
        if line.startswith("dn: "):
            dns.append(line.split("dn: ", 1)[1].strip())
        elif line.startswith("dn:: "):
            b64 = line.split("dn:: ", 1)[1].strip()
            try:
                dns.append(base64.b64decode(b64).decode("utf-8"))
            except Exception:
                continue
    return dns


def prune_users(uri, bind_dn, bind_password, ou_dn):
    args = ["ldapsearch"] + ldap_base_args(uri, bind_dn, bind_password) + [
        "-LLL",
        "-o",
        "ldif-wrap=no",
        "-b",
        ou_dn,
        "(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person))",
        "dn",
    ]
    proc = run_cmd(args, check=False)
    if proc.returncode != 0 and "No such object" not in proc.stderr:
        raise RuntimeError(
            "ldapsearch failed (rc={}):\n{}".format(proc.returncode, proc.stderr)
        )
    dns = parse_dns(proc.stdout)
    if not dns:
        return 0

    with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
        tmp.write("\n".join(dns) + "\n")
        tmp_path = tmp.name

    try:
        proc_del = run_cmd(
            ["ldapdelete"]
            + ldap_base_args(uri, bind_dn, bind_password)
            + ["-c", "-f", tmp_path],
            check=False,
        )
        if proc_del.returncode != 0:
            raise RuntimeError(
                "ldapdelete failed (rc={}):\n{}".format(
                    proc_del.returncode, proc_del.stderr
                )
            )
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return len(dns)


def md5_ldap_hash(password):
    digest = hashlib.md5(password.encode("utf-8")).digest()
    return "{MD5}" + base64.b64encode(digest).decode("ascii")


def build_ldif(entries):
    blocks = []
    for entry in entries:
        lines = []
        for attr, value in entry:
            line = format_ldif_line(attr, value)
            if line is not None:
                lines.append(line)
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks) + ("\n" if blocks else "")


def parse_ou_components(raw_value):
    if raw_value is None:
        return []
    text = raw_value.strip()
    if not text:
        return []
    parts = [p.strip() for p in text.split(",") if p.strip()]
    ou_parts = []
    dc_parts = []
    for part in parts:
        lower = part.lower()
        if lower.startswith("ou="):
            ou_parts.append(part)
        elif lower.startswith("dc="):
            dc_parts.append(part)
        else:
            ou_parts.append("ou={}".format(part))
    return ou_parts, dc_parts


def build_ou_dn(raw_value, base_dn):
    ou_parts, dc_parts = parse_ou_components(raw_value)
    if dc_parts:
        base_dn = ",".join(dc_parts)
    ou_dn = ",".join(ou_parts + [base_dn]) if ou_parts else base_dn
    return ou_dn, ou_parts, base_dn


def ensure_ou_path(uri, bind_dn, bind_password, ou_parts, base_dn, ensured):
    current_base = base_dn
    for part in reversed(ou_parts):
        ou_dn = "{},{}".format(part, current_base)
        if ou_dn not in ensured:
            ou_value = part.split("=", 1)[1]
            ensure_ou(uri, bind_dn, bind_password, ou_dn, ou_value)
            ensured.add(ou_dn)
        current_base = ou_dn
    return current_base


def main():
    parser = argparse.ArgumentParser(
        description="Import LDAP users from CSV into OUs."
    )
    parser.add_argument(
        "--csv",
        default="/workfiles/ldap_users.csv",
        help="Path to CSV file.",
    )
    parser.add_argument("--ldap-uri", default="ldap://127.0.0.1")
    parser.add_argument("--base-dn", default="local.host")
    parser.add_argument("--users-ou", default="Users")
    parser.add_argument("--bind-dn", default=None)
    parser.add_argument("--bind-password", default=None)
    parser.add_argument("--gid", type=int, default=None)
    parser.add_argument("--uid-start", type=int, default=1000)
    parser.add_argument(
        "--prune",
        action="store_true",
        help="Delete existing users from the target OU before import.",
    )
    args = parser.parse_args()

    bind_dn = args.bind_dn or "cn=admin,{}".format(args.base_dn)
    bind_password = (
        args.bind_password
        or os.environ.get("LDAP_ADMIN_PASSWORD")
        or os.environ.get("LDAP_CONFIG_PASSWORD")
    )
    if not bind_password:
        print("Missing bind password (use --bind-password or LDAP_ADMIN_PASSWORD).")
        return 2

    users_ou = args.users_ou
    ou_dn, _, base_dn = build_ou_dn(users_ou, args.base_dn)
    if args.prune:
        try:
            pruned = prune_users(args.ldap_uri, bind_dn, bind_password, ou_dn)
        except RuntimeError as exc:
            print(str(exc))
            return 3
        print("Pruned: {}".format(pruned))
        return 0

    ensured_ou_dns = set()
    ou_value_default = users_ou
    ou_parts_default, _ = parse_ou_components(users_ou)
    if ou_parts_default:
        ensure_ou_path(
            args.ldap_uri, bind_dn, bind_password, ou_parts_default, base_dn, ensured_ou_dns
        )
    else:
        ensure_ou(args.ldap_uri, bind_dn, bind_password, ou_dn, ou_value_default)

    csv_text = decode_csv(args.csv)
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)
    total_rows = len(rows)
    header_map = {
        normalize_header(RUS_DEPT): "department",
        normalize_header("OU"): "ou",
        normalize_header(RUS_LAST): "last_name",
        normalize_header(RUS_FIRST): "first_name",
        normalize_header("CN"): "cn",
        normalize_header("User ID"): "uid",
        normalize_header("Password"): "password",
    }

    existing_uids, max_uid, uid_dns = get_existing_uids(
        args.ldap_uri, bind_dn, bind_password, args.base_dn
    )
    next_uid = max(max_uid + 1, args.uid_start)
    gid_number = args.gid if args.gid is not None else 500

    entries = []
    seen_uids = set()
    seen_uid_row = {}
    skipped = []
    created = []
    created_rows = []
    invalid_rows = 0
    skipped_rows = []

    for idx, row in enumerate(rows, start=2):
        if not row:
            invalid_rows += 1
            skipped_rows.append(
                {"row": idx, "uid": "", "cn": "", "dn": "", "reason": "empty row"}
            )
            continue
        norm_row = {}
        for key, value in row.items():
            if key is None:
                continue
            norm_row[normalize_header(key)] = (value or "").strip()

        def get_field(field_key):
            for header_norm, canonical in header_map.items():
                if canonical == field_key and header_norm in norm_row:
                    return norm_row[header_norm]
            return ""

        uid = get_field("uid")
        password = get_field("password")
        last_name = get_field("last_name")
        first_name = get_field("first_name")
        cn = get_field("cn") or "{} {}".format(first_name, last_name).strip()
        ou_field = get_field("ou") or users_ou
        row_ou_dn, row_ou_parts, row_base_dn = build_ou_dn(ou_field, base_dn)
        if not uid or not password:
            invalid_rows += 1
            reason_parts = []
            if not uid:
                reason_parts.append("missing uid")
            if not password:
                reason_parts.append("missing password")
            skipped_rows.append(
                {
                    "row": idx,
                    "uid": uid,
                    "cn": cn,
                    "dn": "cn={},{}".format(cn, row_ou_dn) if cn else "",
                    "reason": ", ".join(reason_parts),
                }
            )
            continue
        if uid in existing_uids or uid in seen_uids:
            if uid in existing_uids:
                dn_info = uid_dns.get(uid)
                reason = "uid exists in LDAP"
                if dn_info:
                    reason += " ({})".format(dn_info)
            else:
                first_row = seen_uid_row.get(uid)
                reason = "duplicate uid in CSV"
                if first_row:
                    reason += " (first at row {})".format(first_row)
            skipped_rows.append(
                {
                    "row": idx,
                    "uid": uid,
                    "cn": cn,
                    "dn": dn_info or "cn={},{}".format(cn, row_ou_dn),
                    "reason": reason,
                }
            )
            skipped.append(uid)
            continue

        uid_number = next_uid
        next_uid += 1
        if row_ou_parts:
            ensure_ou_path(
                args.ldap_uri,
                bind_dn,
                bind_password,
                row_ou_parts,
                row_base_dn,
                ensured_ou_dns,
            )
        user_dn = "cn={},{}".format(cn, row_ou_dn)

        entry = [
            ("dn", user_dn),
            ("objectClass", "top"),
            ("objectClass", "inetOrgPerson"),
            ("objectClass", "posixAccount"),
            ("objectClass", "shadowAccount"),
            ("cn", cn),
            ("sn", last_name),
            ("givenName", first_name),
            ("uid", uid),
            ("uidNumber", uid_number),
            ("gidNumber", gid_number),
            ("homeDirectory", "/home/{}".format(uid)),
            ("loginShell", "/bin/bash"),
            ("userPassword", md5_ldap_hash(password)),
        ]
        entries.append(entry)
        seen_uids.add(uid)
        seen_uid_row[uid] = idx
        created.append(uid)
        created_rows.append(
            {
                "row": idx,
                "uid": uid,
                "cn": cn,
                "dn": user_dn,
                "uidNumber": uid_number,
                "gidNumber": gid_number,
            }
        )

    if not entries:
        print("Total rows: {}".format(total_rows))
        if invalid_rows:
            print("Invalid rows skipped: {}".format(invalid_rows))
        if skipped:
            print("Skipped (existing/duplicate): {}".format(", ".join(skipped)))
        if skipped_rows:
            print("\nSkipped details:")
            print_table(
                skipped_rows,
                [
                    ("row", "Row"),
                    ("uid", "UID"),
                    ("cn", "CN"),
                    ("dn", "DN"),
                    ("reason", "Reason"),
                ],
            )
        print("No new users to add.")
        return 0

    ldif = build_ldif(entries)
    with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
        tmp.write(ldif)
        tmp_path = tmp.name

    try:
        run_cmd(
            ["ldapadd"]
            + ldap_base_args(args.ldap_uri, bind_dn, bind_password)
            + ["-c", "-f", tmp_path]
        )
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    print("Total rows: {}".format(total_rows))
    print("Added: {}".format(len(created)))
    if invalid_rows:
        print("Invalid rows skipped: {}".format(invalid_rows))
    if skipped:
        print("Skipped (existing/duplicate): {}".format(", ".join(skipped)))
    if created_rows:
        print("\nCreated accounts:")
        print_table(
            created_rows,
            [
                ("row", "Row"),
                ("uid", "UID"),
                ("cn", "CN"),
                ("dn", "DN"),
                ("uidNumber", "UID#"),
                ("gidNumber", "GID#"),
            ],
        )
    if skipped_rows:
        print("\nSkipped details:")
        print_table(
            skipped_rows,
            [("row", "Row"), ("uid", "UID"), ("cn", "CN"), ("dn", "DN"), ("reason", "Reason")],
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
