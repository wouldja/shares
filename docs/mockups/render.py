#!/usr/bin/env python3
"""Write the three interface mockups as fixed-size HTML pages.

The pages are examples. They are not a reading of this machine's shares.
"""

from pathlib import Path

OUT = Path(__file__).resolve().parent

CSS = r"""
:root {
  --bg: #16161e;
  --inset: #0f0f18;
  --fg: #a1a3ad;
  --bright: #bcbec8;
  --secondary: #7e8089;
  --accent: #7c8099;
  --border: #424247;
  --green: #73876b;
  --yellow: #907f63;
  --red: #a17675;
  --hairline: rgba(161, 163, 173, 0.12);
  --selected: rgba(161, 163, 173, 0.18);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body {
  width: 1200px; height: 760px; overflow: hidden;
  background: var(--bg); color: var(--fg);
  font-family: "JetBrainsMono NF", "JetBrains Mono", ui-monospace, monospace;
  font-size: 12px; line-height: 1.35;
}
.app { position: relative; width: 1200px; height: 760px; display: flex; flex-direction: column; border: 1px solid var(--border); }
.top, .bottom { flex: none; display: flex; align-items: center; }
.top { height: 42px; justify-content: space-between; padding: 0 14px 0 16px; border-bottom: 1px solid var(--hairline); }
.bottom { height: 36px; gap: 16px; padding: 0 16px; border-top: 1px solid var(--hairline); color: var(--secondary); }
.brand { color: var(--bright); font-weight: 700; }
.top-hints, .hint { display: flex; align-items: center; gap: 8px; }
.top-hints { gap: 14px; color: var(--secondary); }
kbd {
  display: inline-flex; align-items: center; justify-content: center;
  min-width: 16px; height: 16px; padding: 0 4px;
  background: var(--inset); border: 1px solid var(--border);
  color: var(--bright); font-family: inherit; font-size: 11px; font-weight: 700;
}
.body { flex: 1; display: flex; min-height: 0; }
.side { width: 196px; flex: none; border-right: 1px solid var(--hairline); padding: 8px; display: flex; flex-direction: column; }
.section {
  height: 32px; display: flex; align-items: center; padding: 0 8px;
  color: var(--secondary); font-weight: 700; letter-spacing: 0.06em; font-size: 11px;
}
.nav { height: 28px; display: flex; align-items: center; gap: 8px; padding: 0 8px; }
.nav.selected { background: var(--selected); color: var(--bright); }
.dot { width: 6px; height: 6px; background: var(--green); flex: none; }
.nav .count { margin-left: auto; color: var(--secondary); }
.reach { padding: 4px 8px 10px; }
.reach .host { color: var(--bright); margin-top: 8px; }
.reach .via { color: var(--secondary); font-size: 11px; }
.side-foot { margin-top: auto; padding: 8px; color: var(--secondary); border-top: 1px solid var(--hairline); }
.side-foot strong { color: var(--fg); font-weight: 500; }
.main { flex: 1; min-width: 0; display: flex; flex-direction: column; padding: 18px 18px 0; }
.main-head { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 14px; }
h1 { font-size: 14px; font-weight: 700; color: var(--bright); }
.sub { color: var(--secondary); margin-top: 4px; }
.btn {
  height: 28px; padding: 0 10px; display: inline-flex; align-items: center; gap: 8px;
  background: transparent; border: 1px solid var(--border); color: var(--fg);
  font-family: inherit; font-size: 12px;
}
.btn.primary { border-color: var(--accent); color: var(--accent); }
.btn.danger { border-color: var(--red); color: var(--red); }
.filter {
  height: 32px; display: flex; align-items: center; gap: 8px; padding: 0 10px;
  background: var(--inset); border: 1px solid var(--border); color: var(--secondary); margin-bottom: 8px;
}
.row {
  min-height: 52px; display: grid; grid-template-columns: 1fr auto; column-gap: 12px;
  align-items: center; padding: 8px 10px; border-bottom: 1px solid var(--hairline);
}
.row.selected { background: var(--selected); }
.name { color: var(--fg); }
.row.selected .name { color: var(--bright); }
.path, .meta, .quiet { color: var(--secondary); }
.meta { text-align: right; font-size: 11px; }
.badges { display: flex; gap: 6px; justify-content: flex-end; }
.badge { padding: 1px 6px; border: 1px solid var(--border); color: var(--secondary); font-size: 11px; }
.badge.warn { border-color: var(--yellow); color: var(--yellow); }
.detail {
  width: 340px; flex: none; border-left: 1px solid var(--hairline);
  padding: 18px; display: flex; flex-direction: column; gap: 14px;
}
.detail h2 { font-size: 16px; font-weight: 700; color: var(--bright); }
.label { color: var(--secondary); font-size: 11px; font-weight: 700; letter-spacing: 0.06em; margin-bottom: 6px; }
.addr {
  background: var(--inset); border: 1px solid var(--border); padding: 8px 10px;
  display: flex; flex-direction: column; gap: 4px;
}
.addr .line { overflow-wrap: anywhere; }
.addr-row { display: flex; justify-content: flex-end; }
.switch-row { height: 28px; display: flex; align-items: center; justify-content: space-between; }
.switch {
  width: 42px; height: 22px; padding: 2px; border: 1px solid rgba(161, 163, 173, 0.40);
  background: var(--inset); display: flex; align-items: center; flex: none;
}
.switch.on { border-color: transparent; background: #3a3a46; justify-content: flex-end; }
.thumb { width: 16px; height: 16px; background: var(--secondary); }
.switch.on .thumb { background: var(--fg); }
.fact { color: var(--fg); margin-top: 2px; overflow-wrap: anywhere; }
.fact span { color: var(--secondary); }
.advanced {
  height: 32px; display: flex; align-items: center; justify-content: space-between;
  border-top: 1px solid var(--hairline); border-bottom: 1px solid var(--hairline);
}
.chev { color: var(--secondary); }
.detail-foot { margin-top: auto; display: flex; flex-direction: column; align-items: flex-start; gap: 8px; }
.bottom b { color: var(--fg); font-weight: 500; }
.shade { position: absolute; inset: 0; background: rgba(0, 0, 0, 0.60); }
.dialog {
  position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%);
  width: 420px; background: var(--bg); border: 1px solid var(--border); padding: 18px;
}
.dialog h3 { font-size: 16px; font-weight: 700; color: var(--bright); margin-bottom: 10px; }
.dialog p { color: var(--secondary); margin-bottom: 10px; }
.field {
  height: 32px; display: flex; align-items: center; padding: 0 10px; margin-bottom: 10px;
  background: var(--inset); border: 1px solid var(--border); color: var(--secondary);
}
.path-row { display: flex; gap: 8px; margin-bottom: 10px; }
.path-row .field { flex: 1; margin-bottom: 0; }
.note { color: var(--yellow); margin-bottom: 10px; }
.actions { display: flex; gap: 8px; }
"""

NAV = [
    ("samba", "Samba", "3"),
    ("nfs", "NFS", "2"),
    ("iscsi", "iSCSI", "2"),
    ("s3", "S3", "2"),
]


def kbd(key):
    return f"<kbd>{key}</kbd>"


def badges(items):
    if not items:
        return '<div class="badges"></div>'
    parts = []
    for text, warn in items:
        klass = "badge warn" if warn else "badge"
        parts.append(f'<span class="{klass}">{text}</span>')
    return '<div class="badges">' + "".join(parts) + "</div>"


def row(item, selected):
    klass = "row selected" if selected else "row"
    return f"""
          <div class="{klass}">
            <div class="name">{item["name"]}</div>
            {badges(item.get("badges", []))}
            <div class="path">{item["path"]}</div>
            <div class="meta">{item["meta"]}</div>
          </div>"""


def switch(label, on):
    klass = "switch on" if on else "switch"
    return f'<div class="switch-row"><span>{label}</span><span class="{klass}"><span class="thumb"></span></span></div>'


def dialog(spec):
    form = spec.get("dialog")
    if not form:
        return ""
    return f"""
    <div class="shade"></div>
    <div class="dialog">
      <h3>{form["title"]}</h3>
      <p>{form["hint"]}</p>
      <div class="field">{form["name"]}</div>
      <div class="path-row">
        <div class="field">{form["path"]}</div>
        <button class="btn">Browse</button>
      </div>
      <p class="note">{form["note"]}</p>
      <div class="actions">
        <button class="btn primary">Create</button>
        <button class="btn">Cancel</button>
      </div>
    </div>"""


def page(spec):
    nav = []
    for key, label, count in NAV:
        klass = "nav selected" if key == spec["id"] else "nav"
        nav.append(f'<div class="{klass}"><span class="dot"></span> {label} <span class="count">{count}</span></div>')
    rows = "\n".join(row(item, i == 0) for i, item in enumerate(spec["rows"]))
    switches = "\n".join(switch(label, on) for label, on in spec.get("switches", []))
    facts = "\n".join(
        f'<div><div class="label">{label}</div><div class="fact">{value}</div></div>'
        for label, value in spec.get("facts", [])
    )
    address_html = "".join(f'<div class="line">{line}</div>' for line in spec["addresses"])
    detail = spec["detail"]
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>shares · {spec["title"]}</title>
<style>{CSS}</style>
</head>
<body>
  <div class="app">
    <header class="top">
      <div class="brand">shares</div>
      <div class="top-hints">
        <span class="hint">{kbd("?")} keys</span>
        <span class="hint">{kbd("Q")} quit</span>
      </div>
    </header>
    <div class="body">
      <aside class="side">
        <div class="section">ON THIS MACHINE</div>
        {"".join(nav)}
        <div class="section" style="margin-top: 10px;">REACHABLE AS</div>
        <div class="reach">
          <div class="host">files.local</div>
          <div class="via">this network</div>
          <div class="host">share.example.net</div>
          <div class="via">other name</div>
        </div>
        <div class="side-foot">{spec["foot"]}</div>
      </aside>
      <section class="main">
        <div class="main-head">
          <div>
            <h1>{spec["title"]}</h1>
            <div class="sub">{spec["sub"]}</div>
          </div>
          <button class="btn primary">New {kbd("N")}</button>
        </div>
        <div class="filter">{kbd("/")} Filter</div>
        <div class="rows">{rows}</div>
      </section>
      <aside class="detail">
        <div>
          <h2>{detail["name"]}</h2>
          <div class="path">{detail["path"]}</div>
        </div>
        <div>
          <div class="label">ADDRESS</div>
          <div class="addr">
            {address_html}
            <div class="addr-row"><button class="btn primary">Copy {kbd("C")}</button></div>
          </div>
        </div>
        <div>{switches}</div>
        {facts}
        <div class="advanced"><span>Advanced</span><span class="chev">{spec["advanced"]} ›</span></div>
        <div class="detail-foot">
          <button class="btn danger">{spec["remove"]} {kbd("D")}</button>
          <div class="quiet">{spec["kept"]}</div>
        </div>
      </aside>
    </div>
    <footer class="bottom">
      <span>{kbd("J")} {kbd("K")} move</span>
      <span>{kbd("1")} {kbd("2")} {kbd("3")} {kbd("4")} service</span>
      <span>{kbd("Space")} enable</span>
      <span><b>placeholder names</b></span>
    </footer>
    {dialog(spec)}
  </div>
</body>
</html>
"""


PAGES = [
    {
        "id": "samba",
        "title": "Samba",
        "sub": "3 shares · smb.service is running",
        "foot": 'Workgroup <strong>WORKGROUP</strong><br>Samba passwords ' + kbd("U"),
        "advanced": "4 keys",
        "remove": "Remove share",
        "kept": "Removes the share only. The folder stays.",
        "rows": [
            {"name": "photos", "path": "/srv/photos", "meta": "quiet", "badges": []},
            {"name": "work", "path": "/srv/work", "meta": "quiet", "badges": [("Read only", False)]},
            {"name": "media", "path": "/srv/media", "meta": "quiet", "badges": [("Guest", True), ("Read only", False)]},
        ],
        "detail": {"name": "photos", "path": "/srv/photos"},
        "addresses": ["smb://files.local/photos", r"\\files\photos"],
        "switches": [("Guest", False), ("Read only", False), ("Browsable", True), ("Inherit permissions", True)],
        "facts": [
            ("WHO", "ada · read and write"),
            ("CONNECTED", "desk <span>· quiet</span>"),
        ],
        "dialog": {
            "title": "New samba",
            "hint": "The folder browser opens so you can pick or create the folder. Arrows and the mouse both move through it.",
            "name": "Name",
            "path": "Folder",
            "note": "The browser is open. Create Folder makes the directory. Arrows, Enter, and the mouse all work there.",
        },
    },
    {
        "id": "nfs",
        "title": "NFS",
        "sub": "2 exports · nfs-server.service is running",
        "foot": "File <strong>/etc/exports.d/shares.exports</strong>",
        "advanced": "export options",
        "remove": "Remove export",
        "kept": "Removes the export only. The folder stays.",
        "rows": [
            {"name": "photos", "path": "/srv/photos", "meta": "1 client", "badges": []},
            {"name": "backup", "path": "/srv/backup", "meta": "quiet", "badges": [("Read only", False)]},
        ],
        "detail": {"name": "photos", "path": "/srv/photos"},
        "addresses": ["files.local:/srv/photos", "nfs://files.local/srv/photos"],
        "switches": [("Read only", False)],
        "facts": [
            ("CLIENTS", "10.0.0.0/24 <span>· rw,sync,no_subtree_check</span>"),
            ("CONNECTED", "quiet"),
        ],
    },
    {
        "id": "iscsi",
        "title": "iSCSI",
        "sub": "2 targets · target.service is running",
        "foot": "Mode <strong>single server</strong>",
        "advanced": "CHAP users",
        "remove": "Remove target",
        "kept": "Removes the target only. The disk image stays.",
        "rows": [
            {"name": "photos", "path": "iqn.2026-10.example.host:photos", "meta": "20G", "badges": []},
            {"name": "backup", "path": "iqn.2026-10.example.host:backup", "meta": "100G", "badges": []},
        ],
        "detail": {"name": "photos", "path": "iqn.2026-10.example.host:photos"},
        "addresses": ["files.local:3260"],
        "switches": [("Write protected", False)],
        "facts": [
            ("BACKING", "fileio <span>· /srv/iscsi/photos.img · 20G</span>"),
            ("PORTAL", "0.0.0.0:3260"),
            ("INITIATOR", "iqn.2026-10.example.client:desk"),
            ("CHAP", "off"),
        ],
    },
    {
        "id": "s3",
        "title": "S3",
        "sub": "2 buckets · minio",
        "foot": "Backends <strong>minio</strong>",
        "advanced": "access",
        "remove": "Remove bucket",
        "kept": "Deletes an empty bucket. Objects stay if the service refuses.",
        "rows": [
            {"name": "photos", "path": "minio", "meta": "minio", "badges": []},
            {"name": "backup", "path": "minio", "meta": "minio", "badges": []},
        ],
        "detail": {"name": "photos", "path": "minio"},
        "addresses": ["s3://photos"],
        "switches": [],
        "facts": [
            ("BACKEND", "minio"),
            ("USAGE", "not reported"),
            ("ACCESS", "ada"),
        ],
    },
]


def main():
    for spec in PAGES:
        path = OUT / f"{spec['id']}.html"
        path.write_text(page(spec), encoding="utf-8")
        print(path)


if __name__ == "__main__":
    main()
