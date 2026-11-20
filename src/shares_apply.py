#!/usr/bin/env python3
"""Apply a Shares plan on this computer.

The plan is JSON on stdin. Paths and commands are allowlisted. Nothing is
passed through a shell, and a share removal never deletes the folder or disk
image. --root is for tests. --check validates the plan and does not write or
run anything. A real apply uses /.
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
PATH_TOKEN = re.compile(r"^[A-Za-z0-9_./ :=+@,%|-]+$")
ACCOUNT = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
SHARE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._$-]{0,80}$")
HOST = re.compile(r"^[A-Za-z0-9_.:/*?-]+$")
SIZE = re.compile(r"^[0-9]+[KMGT]?$")
PORT = re.compile(r"^[0-9]{1,5}$")
POOL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
IQN = re.compile(r"^iqn\.[A-Za-z0-9_.:-]+$")
MODE = re.compile(r"^0[0-7]{3}$")
SECONDS = re.compile(r"^[1-9]$")
RUSTFS = re.compile(r"^http://127\.0\.0\.1:[0-9]{2,5}/rustfs/admin/v3/[A-Za-z0-9_./-]*$")
EXPORTS = re.compile(r"^etc/exports\.d/[A-Za-z0-9][A-Za-z0-9._-]*\.exports$")
CHAP = re.compile(
    r"^/iscsi/(iqn\.[A-Za-z0-9_.:-]+)/tpg1/acls/([A-Za-z0-9_.:-]+) set auth password=([A-Za-z0-9_./:=+@,%|-]+)$"
)
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
DANGEROUS = {"include", "preexec", "postexec", "root preexec", "root postexec", "magic script"}


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def token_ok(arg):
    return bool(arg) and ".." not in arg and TOKEN.match(arg) is not None


def share_name_ok(name):
    return SHARE.match(name) is not None


def account_ok(name):
    return ACCOUNT.match(name) is not None


def absolute_ok(path):
    if not path.startswith("/") or "\n" in path or "\r" in path:
        return False
    return ".." not in path.split("/")


def path_arg_ok(path):
    return absolute_ok(path) and ".." not in path and PATH_TOKEN.match(path) is not None


def iqn_ok(iqn):
    return token_ok(iqn) and IQN.match(iqn) is not None


def port_ok(port):
    if PORT.match(port) is None:
        return False
    value = int(port)
    return 1 <= value <= 65535


def chap_ok(secret):
    return TOKEN.match(secret) is not None and ".." not in secret


def size_ok(size):
    return SIZE.match(size) is not None


def host_ok(host):
    return HOST.match(host) is not None and ".." not in host


def iqn_from(path, suffix):
    prefix = "/iscsi/"
    if not path.startswith(prefix) or not path.endswith(suffix):
        return None
    iqn = path[len(prefix) : len(path) - len(suffix)]
    return iqn if iqn_ok(iqn) else None


def file_allowed(rel):
    if not isinstance(rel, str) or ".." in rel or rel.startswith("/") or "\\" in rel:
        return False
    return rel in FILES or rel == "etc/exports" or EXPORTS.match(rel) is not None


def already_exists(message):
    text = message.lower()
    return "already exists" in text or "file exists" in text


def dangerous_shares(body):
    for line in body.split("\n"):
        trimmed = line.strip()
        if not trimmed or trimmed[0] in "#;[":
            continue
        if "=" not in trimmed:
            continue
        key = " ".join(trimmed.split("=", 1)[0].strip().lower().split())
        if key in DANGEROUS:
            return True
    return False


def curl_allowed(args):
    if len(args) < 3 or args[1] != "-sf":
        return False
    index = 2
    while index < len(args) - 1:
        if args[index] in {"--connect-timeout", "--max-time"} and index + 1 < len(args) - 1:
            if SECONDS.match(args[index + 1]) is None:
                return False
            index += 2
            continue
        if args[index] == "-X" and index + 1 < len(args) - 1:
            if args[index + 1] not in {"PUT", "DELETE", "GET"}:
                return False
            index += 2
            continue
        return False
    if index != len(args) - 1:
        return False
    return RUSTFS.match(args[index]) is not None and token_ok(args[index])


def iscsi_tool_allowed(tool, args, stdin_text):
    if tool not in {"targetcli", "gwcli"}:
        return False
    if len(args) == 1:
        if not stdin_text.endswith("\n"):
            return False
        line = stdin_text[:-1]
        if "\n" in line or "\r" in line:
            return False
        match = CHAP.match(line)
        return match is not None and iqn_ok(match.group(1)) and token_ok(match.group(2)) and chap_ok(match.group(3))
    if stdin_text:
        return False
    if len(args) == 2 and tool == "targetcli" and args[1] == "saveconfig":
        return True
    if len(args) == 4 and args[1] == "/iscsi" and args[2] in {"create", "delete"} and iqn_ok(args[3]):
        return True
    if (
        tool == "targetcli"
        and len(args) == 4
        and args[2] == "delete"
        and args[1] in {"/backstores/fileio", "/backstores/block"}
        and share_name_ok(args[3])
        and token_ok(args[3])
    ):
        return True
    if (
        tool == "targetcli"
        and len(args) == 5
        and args[1] == "/backstores/block"
        and args[2] == "create"
        and share_name_ok(args[3])
        and token_ok(args[3])
        and path_arg_ok(args[4])
    ):
        return True
    if (
        tool == "targetcli"
        and len(args) == 6
        and args[1] == "/backstores/fileio"
        and args[2] == "create"
        and share_name_ok(args[3])
        and token_ok(args[3])
        and path_arg_ok(args[4])
        and size_ok(args[5])
    ):
        return True
    if (
        tool == "targetcli"
        and len(args) == 5
        and args[2] == "set"
        and args[3] == "attribute"
        and args[4] == "write_protect=1"
        and args[1].startswith("/backstores/fileio/")
    ):
        name = args[1][len("/backstores/fileio/") :]
        return share_name_ok(name) and token_ok(name)
    if len(args) == 4 and args[2] == "create" and iqn_from(args[1], "/tpg1/luns"):
        store = args[3]
        return (share_name_ok(store) and token_ok(store)) or (store.startswith("/backstores/") and token_ok(store))
    if len(args) == 5 and args[2] == "create" and iqn_from(args[1], "/tpg1/portals"):
        return host_ok(args[3]) and token_ok(args[3]) and port_ok(args[4])
    if len(args) == 4 and args[2] == "create" and iqn_from(args[1], "/tpg1/acls"):
        return token_ok(args[3])
    if (
        len(args) == 5
        and args[2] == "set"
        and args[3] == "auth"
        and args[4].startswith("userid=")
        and args[1].startswith("/iscsi/")
        and "/tpg1/acls/" in args[1]
    ):
        marker = "/tpg1/acls/"
        at = args[1].index(marker)
        iqn_part = args[1][len("/iscsi/") : at]
        initiator = args[1][at + len(marker) :]
        userid = args[4][len("userid=") :]
        return iqn_ok(iqn_part) and token_ok(initiator) and bool(userid) and token_ok(userid) and token_ok(args[4])
    if len(args) == 3 and args[2] in {"enable", "disable"} and iqn_from(args[1], "/tpg1"):
        return True
    return False


def rbd_allowed(args):
    if len(args) != 5 or args[1] != "create" or args[3] != "--size":
        return False
    image = args[2]
    if image.count("/") != 1 or ".." in image:
        return False
    pool, name = image.split("/", 1)
    return POOL.match(pool) is not None and share_name_ok(name) and token_ok(name) and size_ok(args[4]) and token_ok(image)


def mc_allowed(args, stdin_text):
    if len(args) == 3 and args[1] in {"mb", "rb"} and args[2].startswith("local/") and stdin_text == "":
        name = args[2][len("local/") :]
        return share_name_ok(name) and token_ok(args[2])
    if len(args) == 6 and args[1:5] == ["admin", "user", "remove", "local"] and stdin_text == "":
        return (account_ok(args[5]) or share_name_ok(args[5])) and token_ok(args[5])
    if args == ["mc", "admin", "user", "add", "local"]:
        if not stdin_text.endswith("\n") or "\r" in stdin_text:
            return False
        lines = stdin_text.split("\n")
        if len(lines) != 3 or lines[2] != "" or lines[1] == "":
            return False
        return account_ok(lines[0]) or share_name_ok(lines[0])
    return False


def garage_allowed(args):
    if len(args) != 4 or args[1] not in {"bucket", "key"} or args[2] not in {"create", "delete"}:
        return False
    return share_name_ok(args[3]) and token_ok(args[3])


def rados_allowed(args):
    if len(args) == 4 and args[1:3] == ["bucket", "rm"] and args[3].startswith("--bucket="):
        name = args[3][len("--bucket=") :]
        return share_name_ok(name) and token_ok(args[3])
    if len(args) == 4 and args[1:3] == ["user", "rm"] and args[3].startswith("--uid="):
        name = args[3][len("--uid=") :]
        return (account_ok(name) or share_name_ok(name)) and token_ok(args[3])
    if len(args) == 5 and args[1:3] == ["user", "create"] and args[3].startswith("--uid=") and args[4].startswith("--display-name="):
        uid = args[3][len("--uid=") :]
        display = args[4][len("--display-name=") :]
        return uid == display and (account_ok(uid) or share_name_ok(uid)) and token_ok(args[3]) and token_ok(args[4])
    return False


def allowed(args, stdin_text=""):
    if not args:
        return False
    program = args[0]
    if program == "exportfs":
        return stdin_text == "" and args == ["exportfs", "-ra"]
    if program == "systemctl":
        if stdin_text or len(args) != 3:
            return False
        verb, unit = args[1], args[2]
        return verb in {"start", "reload", "restart", "is-active"} and unit in UNITS
    if program == "smbpasswd":
        if len(args) == 4 and args[1] == "-s" and args[2] == "-a":
            return account_ok(args[3])
        if len(args) == 3 and args[1] == "-x":
            return stdin_text == "" and account_ok(args[2])
        return False
    if program == "pdbedit":
        return stdin_text == "" and args == ["pdbedit", "-L"]
    if program in {"targetcli", "gwcli"}:
        return iscsi_tool_allowed(program, args, stdin_text)
    if program == "rbd":
        return stdin_text == "" and rbd_allowed(args)
    if program == "mc":
        return mc_allowed(args, stdin_text)
    if program == "garage":
        return stdin_text == "" and garage_allowed(args)
    if program == "radosgw-admin":
        return stdin_text == "" and rados_allowed(args)
    if program == "mkdir":
        return stdin_text == "" and len(args) == 3 and args[1] == "-p" and path_arg_ok(args[2])
    if program == "chmod":
        return stdin_text == "" and len(args) == 3 and MODE.match(args[1]) is not None and path_arg_ok(args[2])
    if program == "curl":
        return stdin_text == "" and curl_allowed(args)
    return False


def mentioned(path, files):
    for item in files:
        body = item.get("body", "")
        if isinstance(body, str) and path and path in body:
            return True
    return False


def command_ok(command, files):
    args = command.get("args", [])
    stdin_text = command.get("input", "")
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        return False
    if not isinstance(stdin_text, str) or not allowed(args, stdin_text):
        return False
    if args[0] in {"mkdir", "chmod"}:
        return mentioned(args[-1], files)
    return True


def parse_args(argv):
    root = "/"
    check = False
    index = 0
    while index < len(argv):
        if argv[index] == "--check":
            check = True
            index += 1
            continue
        if argv[index] == "--root" and index + 1 < len(argv):
            root = argv[index + 1]
            index += 2
            continue
        fail("Unknown argument.")
    if not root.startswith("/") or ".." in root.split("/"):
        fail("The apply root has to be an absolute path.")
    return root, check


def restore(previous):
    for dest, existed, body, mode in reversed(previous):
        if not existed:
            try:
                os.remove(dest)
            except FileNotFoundError:
                pass
            continue
        parent = os.path.dirname(dest)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(dest, "wb") as handle:
            handle.write(body)
        os.chmod(dest, stat.S_IMODE(mode))


def main():
    root, check = parse_args(sys.argv[1:])
    try:
        plan = json.load(sys.stdin)
    except json.JSONDecodeError:
        fail("The request was not valid.")
    if not isinstance(plan, dict):
        fail("The request was not valid.")
    files = plan.get("files", [])
    commands = plan.get("commands", [])
    if not isinstance(files, list) or not isinstance(commands, list):
        fail("The request was not valid.")
    for item in files:
        if not isinstance(item, dict):
            fail("The request was not valid.")
        rel = item.get("path", "")
        body = item.get("body", "")
        if not isinstance(body, str) or not file_allowed(rel):
            fail("Refusing to write " + str(rel))
        if rel == "etc/samba/shares.conf" and dangerous_shares(body):
            fail("Shares will not write a Samba key that runs a program.")
    for command in commands:
        if not isinstance(command, dict) or not command_ok(command, files):
            args = command.get("args", []) if isinstance(command, dict) else []
            shown = " ".join(arg for arg in args if isinstance(arg, str))
            fail("Refusing to run " + shown)
    if check:
        return
    previous = []
    try:
        for item in files:
            rel = item["path"]
            dest = os.path.join(root, rel)
            existed = os.path.isfile(dest)
            body = b""
            mode = 0o644
            if existed:
                with open(dest, "rb") as handle:
                    body = handle.read()
                mode = os.stat(dest).st_mode
            previous.append((dest, existed, body, mode))
            parent = os.path.dirname(dest)
            if parent:
                os.makedirs(parent, exist_ok=True)
            temporary = dest + ".shares-new"
            file_mode = 0o600 if rel.endswith(".json") else 0o644
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, file_mode)
            try:
                os.write(fd, item["body"].encode())
            finally:
                os.close(fd)
            os.replace(temporary, dest)
        for command in commands:
            argv = command.get("args", [])
            completed = subprocess.run(argv, input=command.get("input", ""), text=True, capture_output=True)
            if completed.stdout:
                sys.stdout.write(completed.stdout)
            if completed.returncode == 0:
                continue
            message = completed.stderr + " " + completed.stdout
            if argv and argv[0] in {"targetcli", "gwcli", "rbd", "mkdir"} and already_exists(message):
                continue
            why = completed.stderr.strip() or completed.stdout.strip() or (argv[0] + " failed")
            raise RuntimeError(why)
    except Exception as error:
        if previous:
            restore(previous)
        message = str(error)
        if previous and "restored" not in message:
            message += "\nThe previous files were restored."
        fail(message)


if __name__ == "__main__":
    main()
