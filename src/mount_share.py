#!/usr/bin/env python3
"""Mount an smb:// location and print the local folder GVfs gives it.

The desktop file manager opens folders, not smb:// addresses. Nothing is
registered for that scheme, so asking the portal to open one shows "No apps
available". Mounting here puts the share under GVfs, where the file manager
can open it as a folder.

An empty login tries guest access, which is what listing shares does. A
username and password, when the window has them, are used once and not saved.
A dialog asks only when the server refuses that.
"""

import os
import sys

try:
    import gi

    gi.require_version("Gtk", "4.0")
    from gi.repository import Gio, GLib, Gtk
except Exception:
    print(
        "Could not open the share. Install gvfs-smb and python-gobject.",
        file=sys.stderr,
    )
    raise SystemExit(1)


class Answer(Gio.MountOperation):
    def __init__(self, user, password, anonymous):
        super().__init__()
        self.user = user
        self.password = password
        self.anonymous = anonymous
        self.asked = 0

    def do_ask_password(self, message, default_user, default_domain, flags):
        self.asked += 1
        if self.asked > 1:
            self.reply(Gio.MountOperationResult.ABORTED)
            return
        if self.anonymous or not self.password:
            self.set_anonymous(True)
        else:
            self.set_anonymous(False)
            self.set_username(self.user or default_user or "")
            self.set_password(self.password)
        self.set_password_save(Gio.PasswordSave.NEVER)
        self.reply(Gio.MountOperationResult.HANDLED)

    def do_ask_question(self, message, choices):
        for index, choice in enumerate(choices):
            if "guest" in choice.lower() or "anonymous" in choice.lower():
                self.set_choice(index)
                self.reply(Gio.MountOperationResult.HANDLED)
                return
        self.reply(Gio.MountOperationResult.ABORTED)


def mount(uri, operation):
    location = Gio.File.new_for_uri(uri)
    loop = GLib.MainLoop()
    outcome = {"settled": False, "ok": False, "message": "Could not open the share."}

    def finish(ok, message):
        if outcome["settled"]:
            return
        outcome["settled"] = True
        outcome["ok"] = ok
        outcome["message"] = message
        if loop.is_running():
            loop.quit()

    def mounted(file, result, _data):
        try:
            file.mount_enclosing_volume_finish(result)
        except GLib.Error as error:
            if not error.matches(Gio.io_error_quark(), Gio.IOErrorEnum.ALREADY_MOUNTED):
                finish(False, error.message)
                return
        path = file.get_path()
        if not path:
            try:
                path = file.find_enclosing_mount(None).get_root().get_path()
            except GLib.Error as error:
                finish(False, error.message)
                return
        if not path:
            finish(False, "The share mounted, but it has no folder to open.")
            return
        finish(True, path)

    def timed_out():
        finish(False, "Opening the share timed out.")
        return False

    GLib.timeout_add_seconds(45, timed_out)
    location.mount_enclosing_volume(Gio.MountMountFlags.NONE, operation, None, mounted, None)
    loop.run()
    return outcome


def needs_login(message):
    text = message.lower()
    words = ("password", "logon", "auth", "access denied", "permission", "credential", "login")
    return any(word in text for word in words)


def main():
    if len(sys.argv) != 2 or not sys.argv[1].startswith("smb://") or "\n" in sys.argv[1]:
        print("The share address is not valid.", file=sys.stderr)
        return 2

    Gtk.init()
    uri = sys.argv[1]
    user = os.environ.get("SHARES_SMB_USER", "")
    password = os.environ.get("SHARES_SMB_PASSWORD", "")
    if "\n" in user or "\n" in password or "\r" in user or "\r" in password:
        print("The SMB username and password cannot contain line breaks.", file=sys.stderr)
        return 2

    # A bulk connect must not stack a password dialog on every share. The row
    # records the refusal, and opening one share still asks.
    quiet = os.environ.get("SHARES_SMB_NO_PROMPT", "") == "1"
    if password:
        outcome = mount(uri, Answer(user, password, False))
    else:
        outcome = mount(uri, Answer(user, "", True))
    if not outcome["ok"] and needs_login(outcome["message"]) and not quiet:
        outcome = mount(uri, Gtk.MountOperation())
    if outcome["ok"]:
        print(outcome["message"])
        return 0
    if quiet and needs_login(outcome["message"]):
        print("Needs a password.", file=sys.stderr)
        return 1
    print(outcome["message"], file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
