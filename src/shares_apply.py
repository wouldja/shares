#!/usr/bin/env python3
"""Apply a Shares plan on this computer.

The plan is JSON on stdin. Paths and commands are allowlisted. Nothing is
passed through a shell, and a share removal never deletes the folder or disk
image. --root is for tests; a real apply uses /.
"""

import json
import os
import re
import stat
import subprocess
import sys

FILES = {
    "etc/samba/shares.conf",
    "etc/samba/smb.conf",
    "etc/samba/smb.conf.bak",
    "etc/exports.d/shares.exports",
    "etc/shares/iscsi.json",
    "etc/shares/s3.json",
}
TOKEN = re.compile(r"^[A-Za-z0-9_./:=+@,%|-]+$")
UNITS = {
    "smb",
    "smb.service",
    "smbd",
    "smbd.service",
    "nfs-server",
    "nfs-server.service",
    "target",
    "target.service",
    "rtslib-fb-targetctl",
    "rtslib-fb-targetctl.service",
    "minio",
    "garage",
    "ceph-radosgw",
    "rustfs",
}
ACCOUNT = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
RUSTFS = re.compile(r"^http://127\.0\.0\.1:[0-9]{2,5}/rustfs/admin/v3/[A-Za-z0-9_./-]*$")
MODE = re.compile(r"^0[0-7]{3}$")


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def absolute_ok(path):
    return path.startswith("/") and "\n" not in path and ".." not in path.split("/")


def allowed(args):
    if not args:
        return False
    for arg in args:
        if not arg or ".." in arg or not TOKEN.match(arg):
            return False
    program = args[0]
    if program == "exportfs":
        return args == ["exportfs", "-ra"]
    if program == "systemctl":
        return len(args) == 3 and args[1] in {"start", "reload", "restart", "is-active"} and args[2] in UNITS
    if program == "smbpasswd":
        if len(args) == 4 and args[1] == "-s" and args[2] == "-a":
            return ACCOUNT.match(args[3]) is not None
        if len(args) == 3 and args[1] == "-x":
            return ACCOUNT.match(args[2]) is not None
        return False
    if program == "pdbedit":
        return args == ["pdbedit", "-L"]
    if program in {"targetcli", "gwcli", "rbd", "mc", "garage", "radosgw-admin"}:
        return 2 <= len(args) <= 12
    if program == "mkdir":
        return len(args) == 3 and args[1] == "-p" and absolute_ok(args[2])
    if program == "chmod":
        return len(args) == 3 and MODE.match(args[1]) is not None and absolute_ok(args[2])
    if program == "curl":
        if len(args) < 3 or args[1] != "-sf":
            return False
        if len(args) == 3:
            url = args[2]
        elif len(args) == 5 and args[2] == "-X" and args[3] in {"PUT", "DELETE", "GET"}:
            url = args[4]
        else:
            return False
        return RUSTFS.match(url) is not None
    return False


def write_file(root, rel, body):
    if rel not in FILES or ".." in rel:
        fail("Refusing to write " + rel)
    dest = os.path.join(root, rel)
    parent = os.path.dirname(dest)
    os.makedirs(parent, exist_ok=True)
    temporary = dest + ".shares-new"
    mode = 0o600 if rel.endswith(".json") else 0o644
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, body.encode())
    finally:
        os.close(fd)
    os.replace(temporary, dest)


def main():
    root = "/"
    args = sys.argv[1:]
    if args[:1] == ["--root"] and len(args) >= 2:
        root = args[1]
        if not root.startswith("/") or ".." in root.split("/"):
            fail("The apply root has to be an absolute path.")
    plan = json.load(sys.stdin)
    for item in plan.get("files", []):
        write_file(root, item.get("path", ""), item.get("body", ""))
    for command in plan.get("commands", []):
        argv = command.get("args", [])
        if not allowed(argv):
            fail("Refusing to run " + " ".join(argv))
        completed = subprocess.run(argv, input=command.get("input", ""), text=True, capture_output=True)
        if completed.stdout:
            sys.stdout.write(completed.stdout)
        if completed.returncode == 0:
            continue
        message = (completed.stderr + " " + completed.stdout).lower()
        if argv[0] in {"targetcli", "gwcli", "rbd", "mkdir"} and "exist" in message:
            continue
        fail(completed.stderr.strip() or completed.stdout.strip() or argv[0] + " failed")


if __name__ == "__main__":
    main()
