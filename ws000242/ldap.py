#!/usr/bin/env python3

import argparse
import base64
import configparser
import csv
import os
import subprocess
import sys
from pathlib import Path


def read_sssd_conf(path: str):
    cfg = {}
    p = Path(path)
    if not p.exists():
        return cfg
    parser = configparser.ConfigParser()
    parser.optionxform = str
    try:
        parser.read(path)
    except Exception:
        return cfg
    for section in ("domain/LDAP", "domain/ldap", "domain/default"):
        if parser.has_section(section):
            for k, v in parser.items(section):
                cfg[k.strip()] = v.strip()
            break
    return cfg


def get_env_first(*names):
    for name in names:
        val = os.environ.get(name)
        if val:
            return val
    return None


def base_from_suffix(suffix: str) -> str:
    parts = [p for p in suffix.split(".") if p]
    return ",".join(f"dc={p}" for p in parts)


def build_cmd(ldap_uri, bind_dn, bind_pw, base, flt, attrs):
    cmd = ["ldapsearch", "-x", "-LLL"]
    if bind_dn and bind_pw is not None:
        cmd.extend(["-D", bind_dn, "-w", bind_pw])
    cmd.extend(["-o", "ldif-wrap=no", "-H", ldap_uri, "-b", base, flt])
    if attrs:
        cmd.extend(attrs)
    return cmd


def run_ldapsearch(cmd):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        print("ldapsearch not found. Install ldap-utils.", file=sys.stderr)
        sys.exit(2)
    if proc.returncode != 0:
        print("ldapsearch failed:", file=sys.stderr)
        if proc.stderr:
            print(proc.stderr.strip(), file=sys.stderr)
        sys.exit(proc.returncode)
    return proc.stdout


def parse_ldif(text: str):
    entries = []
    current = {}
    last_attr = None
    for line in text.splitlines():
        if not line.strip():
            if current:
                entries.append(current)
            current = {}
            last_attr = None
            continue
        if line.startswith(" "):
            if last_attr and last_attr in current:
                current[last_attr][-1] += line[1:]
            continue
        if ":: " in line:
            attr, val = line.split(":: ", 1)
            try:
                val = base64.b64decode(val).decode("utf-8", errors="replace")
            except Exception:
                val = ""
        elif ": " in line:
            attr, val = line.split(": ", 1)
        elif ":" in line:
            attr, val = line.split(":", 1)
            val = val.lstrip()
        else:
            continue
        last_attr = attr
        current.setdefault(attr, []).append(val)
    if current:
        entries.append(current)
    return entries


def dn_to_rdn_value(dn: str):
    if not dn:
        return ""
    first = dn.split(",", 1)[0]
    if "=" in first:
        return first.split("=", 1)[1]
    return first


def pick_first(entry, key, default=""):
    vals = entry.get(key)
    if not vals:
        return default
    return vals[0]


def print_table(headers, rows):
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    line = " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    sep = "-+-".join("-" * w for w in widths)
    print(line)
    print(sep)
    if not rows:
        print("(no data)")
        return
    for row in rows:
        print(" | ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)))


def write_csv(path, headers, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)


def main():
    sssd = read_sssd_conf("/etc/sssd_temp.conf")
    if not sssd:
        sssd = read_sssd_conf("/etc/sssd/sssd.conf")

    suffix_env = get_env_first("LDAP_SUFFIX")
    base_default = base_from_suffix(suffix_env) if suffix_env else None

    parser = argparse.ArgumentParser(description="LDAP reporting helper")
    parser.add_argument("--ldap-uri", default=get_env_first("LDAP_URI", "LDAP_URL") or sssd.get("ldap_uri") or "ldap://srv_ldap:389")
    parser.add_argument("--bind-dn", default=get_env_first("LDAP_BINDDN", "LDAP_BIND_DN") or sssd.get("ldap_default_bind_dn") or "cn=srv_ldap_reader,dc=local,dc=host")
    parser.add_argument("--bind-pw", default=get_env_first("LDAP_BINDPW", "LDAP_BIND_PW", "LDAP_READONLY_USER_PASSWORD", "LDAP_DEFAULT_AUTHTOK") or sssd.get("ldap_default_authtok"))
    parser.add_argument("--base", default=get_env_first("LDAP_BASE") or sssd.get("ldap_search_base") or base_default or "dc=local,dc=host")
    parser.add_argument("--users-base", default=get_env_first("LDAP_USERS_BASE") or sssd.get("ldap_user_search_base") or "ou=Users,dc=local,dc=host")
    parser.add_argument("--groups-base", default=get_env_first("LDAP_GROUPS_BASE") or sssd.get("ldap_group_search_base") or "ou=Groups,dc=local,dc=host")
    parser.add_argument("--group", help="Group CN or DN to limit group member listing")
    parser.add_argument("--group-key", default="cn", help="Attribute used as group key (default: cn)")
    parser.add_argument("--only", choices=["groups", "group-members", "users", "all"], default="all")
    parser.add_argument("--csv-dir", default=".", help="Directory to write CSV files (default: current dir)")
    args = parser.parse_args()

    if not args.base:
        print("LDAP base is not set. Use --base or set LDAP_BASE/LDAP_SUFFIX.", file=sys.stderr)
        sys.exit(2)

    groups_base = args.groups_base or args.base
    users_base = args.users_base or args.base

    group_filter = "(|(objectClass=posixGroup)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))"
    user_filter = "(|(objectClass=person)(objectClass=inetOrgPerson)(objectClass=posixAccount))"

    # Fetch groups
    group_attrs = [args.group_key, "cn", "dn", "member", "memberUid"]
    group_cmd = build_cmd(args.ldap_uri, args.bind_dn, args.bind_pw, groups_base, group_filter, group_attrs)
    group_entries = parse_ldif(run_ldapsearch(group_cmd))

    groups = []
    for e in group_entries:
        dn = pick_first(e, "dn", "")
        name = pick_first(e, args.group_key, "") or pick_first(e, "cn", "") or dn_to_rdn_value(dn) or dn
        members_dn = e.get("member", [])
        members_uid = e.get("memberUid", [])
        groups.append({
            "name": name,
            "dn": dn,
            "members_dn": members_dn,
            "members_uid": members_uid,
        })

    # Fetch users
    user_attrs = ["uid", "cn", "dn", "memberOf"]
    user_cmd = build_cmd(args.ldap_uri, args.bind_dn, args.bind_pw, users_base, user_filter, user_attrs)
    user_entries = parse_ldif(run_ldapsearch(user_cmd))

    users = []
    user_by_dn = {}
    for e in user_entries:
        dn = pick_first(e, "dn", "")
        uid = pick_first(e, "uid", "")
        cn = pick_first(e, "cn", "")
        key = uid or cn or dn_to_rdn_value(dn) or dn
        users.append({"key": key, "dn": dn, "memberOf": e.get("memberOf", [])})
        if dn:
            user_by_dn[dn] = key

    # Build membership from groups
    groups_by_user = {}
    for g in groups:
        gname = g["name"]
        for uid in g["members_uid"]:
            groups_by_user.setdefault(uid, set()).add(gname)
        for mdn in g["members_dn"]:
            key = user_by_dn.get(mdn) or dn_to_rdn_value(mdn) or mdn
            groups_by_user.setdefault(key, set()).add(gname)

    # Add memberOf info if present (fallback)
    for u in users:
        for gdn in u.get("memberOf", []):
            gname = dn_to_rdn_value(gdn) or gdn
            groups_by_user.setdefault(u["key"], set()).add(gname)

    # Output sections
    csv_dir = Path(args.csv_dir)

    rows_groups = []
    for g in sorted(groups, key=lambda x: x["name"].lower()):
        rows_groups.append([g["name"], g["dn"]])

    sel = args.group
    rows_group_members = []
    for g in sorted(groups, key=lambda x: x["name"].lower()):
        if sel:
            if "," in sel and "=" in sel:
                if g["dn"].lower() != sel.lower():
                    continue
            else:
                if g["name"].lower() != sel.lower():
                    continue
        members = []
        for uid in g["members_uid"]:
            members.append(uid)
        for mdn in g["members_dn"]:
            members.append(user_by_dn.get(mdn) or dn_to_rdn_value(mdn) or mdn)
        members = sorted({m for m in members if m})
        rows_group_members.append([g["name"], ", ".join(members) if members else "(empty)"])

    rows_users = []
    for u in sorted(users, key=lambda x: x["key"].lower()):
        groups_list = sorted(groups_by_user.get(u["key"], set()))
        rows_users.append([u["key"], u["dn"], ", ".join(groups_list)])

    if args.only in ("groups", "all"):
        print("\nLDAP groups")
        print_table([args.group_key, "DN"], rows_groups)

    if args.only in ("group-members", "all"):
        print("\nGroup members")
        print_table(["group", "members"], rows_group_members)

    if args.only in ("users", "all"):
        print("\nLDAP users")
        print_table(["user", "DN", "groups"], rows_users)

    # CSV export (always)
    write_csv(csv_dir / "ldap_groups.csv", [args.group_key, "DN"], rows_groups)
    write_csv(csv_dir / "ldap_group_members.csv", ["group", "members"], rows_group_members)
    write_csv(csv_dir / "ldap_users.csv", ["user", "DN", "groups"], rows_users)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
