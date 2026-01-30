#!/usr/bin/env python3
import argparse
import base64
import os
import subprocess
import sys


def run_cmd(args, input_text=None, check=True):
    proc = subprocess.run(
        args,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            "Command failed: {}\nstdout:\n{}\nstderr:\n{}".format(
                " ".join(args), proc.stdout, proc.stderr
            )
        )
    return proc


def ldap_base_args(uri, bind_dn, bind_password):
    return ["-x", "-H", uri, "-D", bind_dn, "-w", bind_password]


def parse_ldif(text):
    entries = []
    current = None
    lines = []
    for line in text.splitlines():
        if line.startswith(" "):
            if lines:
                lines[-1] += line[1:]
        else:
            lines.append(line)
    for line in lines:
        if not line.strip():
            if current:
                entries.append(current)
                current = None
            continue
        if current is None:
            current = {"dn": None, "attrs": {}}
        if line.startswith("dn: "):
            current["dn"] = line.split("dn: ", 1)[1].strip()
        elif line.startswith("dn:: "):
            b64 = line.split("dn:: ", 1)[1].strip()
            current["dn"] = base64.b64decode(b64).decode("utf-8")
        else:
            if ":: " in line:
                key, val = line.split(":: ", 1)
                val = base64.b64decode(val.strip()).decode("utf-8")
            else:
                key, val = line.split(": ", 1)
            key = key.strip()
            current["attrs"].setdefault(key, []).append(val.strip())
    if current:
        entries.append(current)
    return entries


def ldapsearch(uri, bind_dn, bind_password, base, ldap_filter, attrs):
    args = (
        ["ldapsearch"]
        + ldap_base_args(uri, bind_dn, bind_password)
        + ["-LLL", "-o", "ldif-wrap=no", "-b", base, ldap_filter]
        + attrs
    )
    proc = run_cmd(args, check=False)
    if proc.returncode != 0 and "No such object" not in proc.stderr:
        raise RuntimeError(
            "ldapsearch failed (rc={}):\n{}".format(proc.returncode, proc.stderr)
        )
    return parse_ldif(proc.stdout)


def get_group(uri, bind_dn, bind_password, base_dn, cn):
    entries = ldapsearch(
        uri,
        bind_dn,
        bind_password,
        "ou=groups,{}".format(base_dn),
        "(cn={})".format(cn),
        ["dn", "objectClass", "memberUid", "member", "gidNumber"],
    )
    return entries[0] if entries else None


def get_uid_dn(uri, bind_dn, bind_password, base_dn, uid):
    entries = ldapsearch(
        uri, bind_dn, bind_password, base_dn, "(uid={})".format(uid), ["dn"]
    )
    if not entries:
        return None
    return entries[0]["dn"]


def get_all_users(uri, bind_dn, bind_password, base_dn):
    entries = ldapsearch(
        uri,
        bind_dn,
        bind_password,
        "ou=users,{}".format(base_dn),
        "(objectClass=posixAccount)",
        ["dn", "uid"],
    )
    users = []
    for entry in entries:
        uid_list = entry["attrs"].get("uid", [])
        uid = uid_list[0] if uid_list else ""
        users.append((uid, entry["dn"]))
    return users


def ensure_group(
    uri,
    bind_dn,
    bind_password,
    base_dn,
    cn,
    gid_number,
    members,
    member_uids=None,
):
    if not members:
        raise RuntimeError("Group {} requires at least one member".format(cn))
    group_dn = "cn={},ou=groups,{}".format(cn, base_dn)
    existing = get_group(uri, bind_dn, bind_password, base_dn, cn)
    if existing:
        object_classes = set(
            x.lower() for x in existing["attrs"].get("objectClass", [])
        )
        if "groupofnames" not in object_classes:
            delete_group(uri, bind_dn, bind_password, group_dn)
            existing = None

    if not existing:
        ldif_lines = [
            "dn: {}".format(group_dn),
            "objectClass: top",
            "objectClass: groupOfNames",
            "objectClass: extensibleObject",
            "cn: {}".format(cn),
            "gidNumber: {}".format(gid_number),
        ]
        for member in members:
            ldif_lines.append("member: {}".format(member))
        if member_uids:
            for uid in member_uids:
                ldif_lines.append("memberUid: {}".format(uid))
        ldif_lines.append("")
        run_cmd(
            ["ldapadd"] + ldap_base_args(uri, bind_dn, bind_password), "\n".join(ldif_lines)
        )
        return

    ldif_members = [
        "dn: {}".format(group_dn),
        "changetype: modify",
        "replace: member",
    ] + ["member: {}".format(m) for m in members] + [""]
    run_cmd(["ldapmodify"] + ldap_base_args(uri, bind_dn, bind_password), "\n".join(ldif_members))

    if member_uids is not None:
        ldif_uids = [
            "dn: {}".format(group_dn),
            "changetype: modify",
            "replace: memberUid",
        ] + ["memberUid: {}".format(u) for u in member_uids] + [""]
        run_cmd(
            ["ldapmodify"] + ldap_base_args(uri, bind_dn, bind_password),
            "\n".join(ldif_uids),
        )


def delete_group(uri, bind_dn, bind_password, dn):
    run_cmd(["ldapdelete"] + ldap_base_args(uri, bind_dn, bind_password) + [dn])


def main():
    parser = argparse.ArgumentParser(description="Create nested LDAP groups.")
    parser.add_argument("--ldap-uri", default="ldap://srv_ldap")
    parser.add_argument("--base-dn", default="local.host")
    parser.add_argument("--bind-dn", default=None)
    parser.add_argument("--bind-password", default=None)
    parser.add_argument("--users-group", default="SG-USERS")
    parser.add_argument("--share-group", default="SG-RES-SHARE-RW")
    parser.add_argument("--users-source-group", default="SG-SRV-USERS-USERS")
    parser.add_argument("--admins-group", default="SG-SRV-MGMT-ADMINS-SSSD")
    parser.add_argument("--admins-source-group", default="SG-SRV-MGMT-ADMINS")
    parser.add_argument("--gid-users", type=int, default=520)
    parser.add_argument("--gid-share", type=int, default=521)
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

    member_uids = []
    user_dns = []
    missing = []
    source_group = get_group(
        args.ldap_uri, bind_dn, bind_password, args.base_dn, args.users_source_group
    )
    if source_group:
        member_uids = source_group["attrs"].get("memberUid", [])
        for uid in member_uids:
            dn = get_uid_dn(args.ldap_uri, bind_dn, bind_password, args.base_dn, uid)
            if dn:
                user_dns.append(dn)
            else:
                missing.append(uid)

    if not user_dns:
        users = get_all_users(args.ldap_uri, bind_dn, bind_password, args.base_dn)
        member_uids = [uid for uid, _ in users if uid]
        user_dns = [dn for _, dn in users if dn]

    ensure_group(
        args.ldap_uri,
        bind_dn,
        bind_password,
        args.base_dn,
        args.users_group,
        args.gid_users,
        user_dns,
        member_uids,
    )

    users_group_dn = "cn={},ou=groups,{}".format(args.users_group, args.base_dn)
    ensure_group(
        args.ldap_uri,
        bind_dn,
        bind_password,
        args.base_dn,
        args.share_group,
        args.gid_share,
        [users_group_dn],
        None,
    )

    admins_group = get_group(
        args.ldap_uri, bind_dn, bind_password, args.base_dn, args.admins_source_group
    )
    if admins_group:
        admin_uids = admins_group["attrs"].get("memberUid", [])
        admin_dns = []
        for uid in admin_uids:
            dn = get_uid_dn(args.ldap_uri, bind_dn, bind_password, args.base_dn, uid)
            if dn:
                admin_dns.append(dn)
        if admin_dns:
            ensure_group(
                args.ldap_uri,
                bind_dn,
                bind_password,
                args.base_dn,
                args.admins_group,
                522,
                admin_dns,
                admin_uids,
            )

    print("Nested groups ready.")
    if missing:
        print(
            "Missing users from source group not found in LDAP: {}".format(
                ", ".join(missing)
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
