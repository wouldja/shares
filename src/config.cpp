#include "config.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>

namespace {

QString yn(bool value) { return value ? "yes" : "no"; }

bool isYes(const QString &value) {
    const auto v = value.trimmed().toLower();
    return v == "yes" || v == "true" || v == "1";
}

QStringList vfsList(const QString &value) {
    return value.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
}

QString joinVfs(QStringList items) {
    items.removeDuplicates();
    return items.join(' ');
}

void stripKnown(QMap<QString, QString> *extra, const QStringList &keys) {
    for (const auto &key : keys)
        extra->remove(key);
}

} // namespace

bool shareNameOk(const QString &name) {
    static const QRegularExpression re("^[A-Za-z0-9][A-Za-z0-9._$-]{0,80}$");
    return re.match(name).hasMatch();
}

bool absolutePathOk(const QString &path) {
    if (!path.startsWith('/') || path.contains('\n') || path.contains('\r'))
        return false;
    const auto parts = path.split('/');
    for (const auto &part : parts) {
        if (part == "..")
            return false;
    }
    return true;
}

bool nfsHostOk(const QString &host) {
    static const QRegularExpression re("^[A-Za-z0-9_.:/*?-]+$");
    return re.match(host).hasMatch() && !host.contains("..");
}

bool nfsOptionsOk(const QString &options) {
    static const QRegularExpression re("^[A-Za-z0-9_,=:.+-]+$");
    return re.match(options).hasMatch();
}

bool accountNameOk(const QString &name) {
    static const QRegularExpression re("^[a-z_][a-z0-9_-]{0,31}$");
    return re.match(name).hasMatch();
}

bool iscsiSizeOk(const QString &size) {
    static const QRegularExpression re("^[0-9]+[KMGT]?$");
    return re.match(size).hasMatch();
}

bool portOk(const QString &port) {
    static const QRegularExpression re("^[0-9]{1,5}$");
    if (!re.match(port).hasMatch())
        return false;
    bool ok = false;
    const int value = port.toInt(&ok);
    return ok && value >= 1 && value <= 65535;
}

bool chapSecretOk(const QString &secret) {
    static const QRegularExpression token("^[A-Za-z0-9_./:=+@,%|-]+$");
    return token.match(secret).hasMatch() && !secret.contains(QStringLiteral(".."));
}

bool dangerousSambaKey(const QString &key) {
    const auto words = key.trimmed().toLower().split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
    const auto name = words.join(' ');
    return name == "include" || name == "preexec" || name == "postexec" || name == "root preexec"
        || name == "root postexec" || name == "magic script";
}

bool sambaTextHasDangerousKey(const QString &text) {
    for (const auto &line : text.split('\n')) {
        const auto trimmed = line.trimmed();
        if (trimmed.isEmpty() || trimmed.startsWith('#') || trimmed.startsWith(';') || trimmed.startsWith('['))
            continue;
        const auto eq = trimmed.indexOf('=');
        if (eq <= 0)
            continue;
        if (dangerousSambaKey(trimmed.left(eq)))
            return true;
    }
    return false;
}

namespace {

bool tokenOk(const QString &arg) {
    static const QRegularExpression token("^[A-Za-z0-9_./:=+@,%|-]+$");
    return !arg.isEmpty() && !arg.contains(QStringLiteral("..")) && token.match(arg).hasMatch();
}

bool pathArgOk(const QString &path) {
    static const QRegularExpression token("^[A-Za-z0-9_./ :=+@,%|-]+$");
    return absolutePathOk(path) && token.match(path).hasMatch() && !path.contains(QStringLiteral(".."));
}

bool iqnOk(const QString &iqn) {
    static const QRegularExpression re("^iqn\\.[A-Za-z0-9_.:-]+$");
    return tokenOk(iqn) && re.match(iqn).hasMatch();
}

bool iqnFrom(const QString &path, const QString &suffix, QString *iqn) {
    const auto prefix = QStringLiteral("/iscsi/");
    if (!path.startsWith(prefix) || !path.endsWith(suffix) || !iqn)
        return false;
    *iqn = path.mid(prefix.size(), path.size() - prefix.size() - suffix.size());
    return iqnOk(*iqn);
}

bool curlAllowed(const QStringList &args) {
    if (args.size() < 3 || args.at(1) != "-sf")
        return false;
    int index = 2;
    while (index < args.size() - 1) {
        if ((args.at(index) == "--connect-timeout" || args.at(index) == "--max-time") && index + 1 < args.size() - 1) {
            static const QRegularExpression seconds("^[1-9]$");
            if (!seconds.match(args.at(index + 1)).hasMatch())
                return false;
            index += 2;
            continue;
        }
        if (args.at(index) == "-X" && index + 1 < args.size() - 1) {
            const auto method = args.at(index + 1);
            if (method != "PUT" && method != "DELETE" && method != "GET")
                return false;
            index += 2;
            continue;
        }
        return false;
    }
    if (index != args.size() - 1)
        return false;
    static const QRegularExpression rustfs("^http://127\\.0\\.0\\.1:[0-9]{2,5}/rustfs/admin/v3/[A-Za-z0-9_./-]*$");
    return rustfs.match(args.at(index)).hasMatch() && tokenOk(args.at(index));
}

bool iscsiToolAllowed(const QString &tool, const QStringList &args, const QString &input) {
    if (tool != "targetcli" && tool != "gwcli")
        return false;
    if (args.size() == 1) {
        if (!input.endsWith('\n'))
            return false;
        const auto line = input.left(input.size() - 1);
        if (line.contains('\n') || line.contains('\r'))
            return false;
        static const QRegularExpression auth(
            "^/iscsi/(iqn\\.[A-Za-z0-9_.:-]+)/tpg1/acls/([A-Za-z0-9_.:-]+) set auth password=([A-Za-z0-9_./:=+@,%|-]+)$");
        const auto match = auth.match(line);
        return match.hasMatch() && iqnOk(match.captured(1)) && tokenOk(match.captured(2)) && chapSecretOk(match.captured(3));
    }
    if (!input.isEmpty())
        return false;
    if (args.size() == 2 && tool == "targetcli" && args.at(1) == "saveconfig")
        return true;
    if (args.size() == 4 && args.at(1) == "/iscsi" && (args.at(2) == "create" || args.at(2) == "delete") && iqnOk(args.at(3)))
        return true;
    if (tool == "targetcli" && args.size() == 4 && args.at(2) == "delete"
        && (args.at(1) == "/backstores/fileio" || args.at(1) == "/backstores/block") && shareNameOk(args.at(3))
        && tokenOk(args.at(3)))
        return true;
    if (tool == "targetcli" && args.size() == 5 && args.at(1) == "/backstores/block" && args.at(2) == "create"
        && shareNameOk(args.at(3)) && tokenOk(args.at(3)) && pathArgOk(args.at(4)))
        return true;
    if (tool == "targetcli" && args.size() == 6 && args.at(1) == "/backstores/fileio" && args.at(2) == "create"
        && shareNameOk(args.at(3)) && tokenOk(args.at(3)) && pathArgOk(args.at(4)) && iscsiSizeOk(args.at(5)))
        return true;
    if (tool == "targetcli" && args.size() == 5 && args.at(2) == "set" && args.at(3) == "attribute" && args.at(4) == "write_protect=1"
        && args.at(1).startsWith("/backstores/fileio/")) {
        const auto name = args.at(1).mid(QStringLiteral("/backstores/fileio/").size());
        return shareNameOk(name) && tokenOk(name);
    }
    QString iqn;
    if (args.size() == 4 && args.at(2) == "create" && iqnFrom(args.at(1), "/tpg1/luns", &iqn)) {
        const auto store = args.at(3);
        return (shareNameOk(store) && tokenOk(store)) || (store.startsWith("/backstores/") && tokenOk(store));
    }
    if (args.size() == 5 && args.at(2) == "create" && iqnFrom(args.at(1), "/tpg1/portals", &iqn))
        return nfsHostOk(args.at(3)) && tokenOk(args.at(3)) && portOk(args.at(4));
    if (args.size() == 4 && args.at(2) == "create" && iqnFrom(args.at(1), "/tpg1/acls", &iqn))
        return tokenOk(args.at(3));
    if (args.size() == 5 && args.at(2) == "set" && args.at(3) == "auth" && args.at(4).startsWith("userid=")
        && args.at(1).startsWith("/iscsi/") && args.at(1).contains("/tpg1/acls/")) {
        const auto marker = QStringLiteral("/tpg1/acls/");
        const auto at = args.at(1).indexOf(marker);
        const auto iqnPart = args.at(1).mid(QStringLiteral("/iscsi/").size(), at - QStringLiteral("/iscsi/").size());
        const auto initiator = args.at(1).mid(at + marker.size());
        const auto userid = args.at(4).mid(QStringLiteral("userid=").size());
        return iqnOk(iqnPart) && tokenOk(initiator) && !userid.isEmpty() && tokenOk(userid) && tokenOk(args.at(4));
    }
    if (args.size() == 3 && (args.at(2) == "enable" || args.at(2) == "disable") && iqnFrom(args.at(1), "/tpg1", &iqn))
        return true;
    return false;
}

bool rbdAllowed(const QStringList &args) {
    if (args.size() != 5 || args.at(1) != "create" || args.at(3) != "--size")
        return false;
    const auto image = args.at(2);
    const auto slash = image.indexOf('/');
    if (slash <= 0 || slash != image.lastIndexOf('/') || image.contains(QStringLiteral("..")))
        return false;
    const auto pool = image.left(slash);
    const auto name = image.mid(slash + 1);
    static const QRegularExpression poolRe("^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$");
    return poolRe.match(pool).hasMatch() && shareNameOk(name) && tokenOk(name) && iscsiSizeOk(args.at(4)) && tokenOk(image);
}

bool mcAllowed(const QStringList &args, const QString &input) {
    if (args.size() == 3 && (args.at(1) == "mb" || args.at(1) == "rb") && args.at(2).startsWith("local/") && input.isEmpty()) {
        const auto name = args.at(2).mid(QStringLiteral("local/").size());
        return shareNameOk(name) && tokenOk(args.at(2));
    }
    if (args.size() == 6 && args.at(1) == "admin" && args.at(2) == "user" && args.at(3) == "remove" && args.at(4) == "local"
        && input.isEmpty())
        return (accountNameOk(args.at(5)) || shareNameOk(args.at(5))) && tokenOk(args.at(5));
    if (args == QStringList{"mc", "admin", "user", "add", "local"}) {
        if (!input.endsWith('\n') || input.contains('\r'))
            return false;
        const auto lines = input.split('\n');
        if (lines.size() != 3 || !lines.at(2).isEmpty() || lines.at(1).isEmpty())
            return false;
        return (accountNameOk(lines.at(0)) || shareNameOk(lines.at(0))) && !lines.at(1).contains('\n');
    }
    return false;
}

bool garageAllowed(const QStringList &args) {
    if (args.size() != 4 || (args.at(1) != "bucket" && args.at(1) != "key"))
        return false;
    if (args.at(2) != "create" && args.at(2) != "delete")
        return false;
    return shareNameOk(args.at(3)) && tokenOk(args.at(3));
}

bool radosAllowed(const QStringList &args) {
    if (args.size() == 4 && args.at(1) == "bucket" && args.at(2) == "rm" && args.at(3).startsWith("--bucket=")) {
        const auto name = args.at(3).mid(QStringLiteral("--bucket=").size());
        return shareNameOk(name) && tokenOk(args.at(3));
    }
    if (args.size() == 4 && args.at(1) == "user" && args.at(2) == "rm" && args.at(3).startsWith("--uid=")) {
        const auto name = args.at(3).mid(QStringLiteral("--uid=").size());
        return (accountNameOk(name) || shareNameOk(name)) && tokenOk(args.at(3));
    }
    if (args.size() == 5 && args.at(1) == "user" && args.at(2) == "create" && args.at(3).startsWith("--uid=")
        && args.at(4).startsWith("--display-name=")) {
        const auto uid = args.at(3).mid(QStringLiteral("--uid=").size());
        const auto display = args.at(4).mid(QStringLiteral("--display-name=").size());
        return uid == display && (accountNameOk(uid) || shareNameOk(uid)) && tokenOk(args.at(3)) && tokenOk(args.at(4));
    }
    return false;
}

} // namespace

bool commandAllowed(const QStringList &args, const QString &input) {
    if (args.isEmpty())
        return false;
    const auto program = args.first();
    if (program == "exportfs")
        return input.isEmpty() && args == QStringList{"exportfs", "-ra"};
    if (program == "systemctl") {
        if (!input.isEmpty() || args.size() != 3)
            return false;
        const auto verb = args.at(1);
        const auto unit = args.at(2);
        const bool verbOk = verb == "start" || verb == "reload" || verb == "restart" || verb == "is-active";
        const bool unitOk = unit == "smb" || unit == "smb.service" || unit == "smbd" || unit == "smbd.service"
            || unit == "nfs-server" || unit == "nfs-server.service" || unit == "target" || unit == "target.service"
            || unit == "rtslib-fb-targetctl" || unit == "rtslib-fb-targetctl.service" || unit == "minio"
            || unit == "garage" || unit == "ceph-radosgw" || unit == "rustfs";
        return verbOk && unitOk;
    }
    if (program == "smbpasswd") {
        if (args.size() == 4 && args.at(1) == "-s" && args.at(2) == "-a")
            return accountNameOk(args.at(3));
        if (args.size() == 3 && args.at(1) == "-x")
            return input.isEmpty() && accountNameOk(args.at(2));
        return false;
    }
    if (program == "pdbedit")
        return input.isEmpty() && args == QStringList{"pdbedit", "-L"};
    if (program == "targetcli" || program == "gwcli")
        return iscsiToolAllowed(program, args, input);
    if (program == "rbd")
        return input.isEmpty() && rbdAllowed(args);
    if (program == "mc")
        return mcAllowed(args, input);
    if (program == "garage")
        return input.isEmpty() && garageAllowed(args);
    if (program == "radosgw-admin")
        return input.isEmpty() && radosAllowed(args);
    if (program == "mkdir")
        return input.isEmpty() && args.size() == 3 && args.at(1) == "-p" && pathArgOk(args.at(2));
    if (program == "chmod") {
        static const QRegularExpression mode("^0[0-7]{3}$");
        return input.isEmpty() && args.size() == 3 && mode.match(args.at(1)).hasMatch() && pathArgOk(args.at(2));
    }
    // RustFS has no local admin tool. Curl is allowed only against the
    // loopback admin API, never an arbitrary URL. A one-digit connect and
    // total timeout is optional so a dead endpoint cannot hang a save.
    if (program == "curl")
        return input.isEmpty() && curlAllowed(args);
    return false;
}

static void dropDangerous(QMap<QString, QString> *params) {
    const auto keys = params->keys();
    for (const auto &key : keys) {
        if (dangerousSambaKey(key))
            params->remove(key);
    }
}

static QMap<QString, QString> shareParameters(const SambaShare &share) {
    QMap<QString, QString> params = share.extra;
    dropDangerous(&params);
    params["path"] = share.path;
    if (!share.comment.isEmpty())
        params["comment"] = share.comment;
    else
        params.remove("comment");
    params["available"] = yn(share.enabled);
    params["guest ok"] = yn(share.guest);
    params["read only"] = yn(share.readOnly);
    params["browsable"] = yn(share.browsable);
    params["inherit permissions"] = yn(share.inheritPermissions);
    if (!share.validUsers.isEmpty())
        params["valid users"] = share.validUsers;
    else
        params.remove("valid users");

    QStringList vfs = vfsList(params.value("vfs objects"));
    auto drop = [&vfs](const QStringList &names) {
        for (const auto &name : names)
            vfs.removeAll(name);
    };
    drop({"acl_xattr", "shadow_copy2", "ceph_snapshots", "catia", "fruit", "streams_xattr", "full_audit", "ceph"});
    stripKnown(&params, {"map acl inherit", "acl_xattr:ignore system acls", "shadow:snapdir", "shadow:sort",
                         "shadow:format", "fruit:encoding", "fruit:metadata", "fruit:zero_file_id", "fruit:nfs_aces",
                         "full_audit:priority", "full_audit:facility", "full_audit:success", "full_audit:failure",
                         "full_audit:prefix", "ceph:quota", "ceph:layout_pool", "ceph:remount"});

    if (share.windowsAcls) {
        vfs << "acl_xattr";
        params["map acl inherit"] = "yes";
        params["acl_xattr:ignore system acls"] = "yes";
    }
    if (share.shadowCopy && share.shadowKind == "ceph") {
        vfs << "ceph_snapshots";
    } else if (share.shadowCopy) {
        vfs << "shadow_copy2";
        params["shadow:snapdir"] = ".zfs/snapshot";
        params["shadow:sort"] = "desc";
        params["shadow:format"] = "%Y-%m-%d-%H%M%S";
    }
    if (share.macos) {
        vfs << "catia" << "fruit" << "streams_xattr";
        params["fruit:encoding"] = "native";
        params["fruit:metadata"] = "stream";
        params["fruit:zero_file_id"] = "yes";
        params["fruit:nfs_aces"] = "no";
    }
    if (share.audit) {
        vfs << "full_audit";
        params["full_audit:priority"] = "notice";
        params["full_audit:facility"] = "local5";
        params["full_audit:success"] = "connect disconnect mkdir rmdir read write rename";
        params["full_audit:failure"] = "connect";
        params["full_audit:prefix"] = "%u|%I|%S";
    }
    if (!share.quota.isEmpty() || !share.layoutPool.isEmpty() || share.cephRemount)
        vfs << "ceph";
    if (!share.quota.isEmpty())
        params["ceph:quota"] = share.quota;
    if (!share.layoutPool.isEmpty())
        params["ceph:layout_pool"] = share.layoutPool;
    if (share.cephRemount)
        params["ceph:remount"] = "yes";
    if (!vfs.isEmpty())
        params["vfs objects"] = joinVfs(vfs);
    else
        params.remove("vfs objects");
    return params;
}

static SambaShare shareFromParameters(const QString &name, QMap<QString, QString> params) {
    SambaShare share;
    share.name = name;
    share.path = params.take("path");
    share.comment = params.take("comment");
    if (params.contains("available"))
        share.enabled = isYes(params.take("available"));
    share.guest = isYes(params.take("guest ok"));
    if (params.contains("read only"))
        share.readOnly = isYes(params.take("read only"));
    if (params.contains("browsable") || params.contains("browseable"))
        share.browsable = isYes(params.contains("browsable") ? params.take("browsable") : params.take("browseable"));
    share.inheritPermissions = isYes(params.take("inherit permissions"));
    share.validUsers = params.take("valid users");
    const auto vfs = vfsList(params.value("vfs objects"));
    share.windowsAcls = vfs.contains("acl_xattr") && isYes(params.value("map acl inherit"));
    share.shadowCopy = vfs.contains("shadow_copy2") || vfs.contains("ceph_snapshots");
    share.shadowKind = vfs.contains("ceph_snapshots") ? "ceph" : "zfs";
    share.macos = vfs.contains("fruit");
    share.audit = vfs.contains("full_audit");
    share.quota = params.value("ceph:quota");
    share.layoutPool = params.value("ceph:layout_pool");
    share.cephRemount = isYes(params.value("ceph:remount"));
    share.extra = params;
    stripKnown(&share.extra, {"map acl inherit", "acl_xattr:ignore system acls", "shadow:snapdir", "shadow:sort",
                              "shadow:format", "fruit:encoding", "fruit:metadata", "fruit:zero_file_id", "fruit:nfs_aces",
                              "full_audit:priority", "full_audit:facility", "full_audit:success", "full_audit:failure",
                              "full_audit:prefix", "ceph:quota", "ceph:layout_pool", "ceph:remount", "vfs objects"});
    QStringList kept = vfs;
    kept.removeAll("acl_xattr");
    kept.removeAll("shadow_copy2");
    kept.removeAll("ceph_snapshots");
    kept.removeAll("catia");
    kept.removeAll("fruit");
    kept.removeAll("streams_xattr");
    kept.removeAll("full_audit");
    if (share.quota.isEmpty() && share.layoutPool.isEmpty() && !share.cephRemount)
        kept.removeAll("ceph");
    if (!kept.isEmpty())
        share.extra["vfs objects"] = joinVfs(kept);
    dropDangerous(&share.extra);
    return share;
}

static QString writeSection(const QString &name, const QMap<QString, QString> &params) {
    QString out = "[" + name + "]\n";
    for (auto it = params.cbegin(); it != params.cend(); ++it)
        out += "   " + it.key() + " = " + it.value() + "\n";
    return out;
}

QString sambaShareText(const SambaGlobal &global, const QVector<SambaShare> &shares) {
    QMap<QString, QString> params = global.extra;
    dropDangerous(&params);
    params["workgroup"] = global.workgroup.isEmpty() ? "WORKGROUP" : global.workgroup;
    if (!global.serverString.isEmpty())
        params["server string"] = global.serverString;
    else
        params.remove("server string");
    if (!global.logLevel.isEmpty())
        params["log level"] = global.logLevel;
    if (global.macos) {
        QStringList vfs = vfsList(params.value("vfs objects"));
        vfs << "catia" << "fruit" << "streams_xattr";
        params["vfs objects"] = joinVfs(vfs);
        params["fruit:encoding"] = "native";
        params["fruit:metadata"] = "stream";
    }
    QString out = writeSection("global", params);
    for (const auto &share : shares) {
        if (!shareNameOk(share.name) || !absolutePathOk(share.path))
            continue;
        out += "\n" + writeSection(share.name, shareParameters(share));
    }
    return out;
}

SambaConfig parseSamba(const QString &text) {
    SambaConfig config;
    QString section;
    QMap<QString, QMap<QString, QString>> sections;
    const auto lines = text.split('\n');
    for (auto line : lines) {
        // A value may contain '#'. Only a leading hash is a comment.
        const auto trimmed = line.trimmed();
        if (trimmed.startsWith('#') || trimmed.startsWith(';') || trimmed.isEmpty())
            continue;
        if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
            section = trimmed.mid(1, trimmed.size() - 2).trimmed();
            sections[section];
            continue;
        }
        const auto eq = trimmed.indexOf('=');
        if (eq < 0 || section.isEmpty())
            continue;
        const auto key = trimmed.left(eq).trimmed().toLower();
        const auto value = trimmed.mid(eq + 1).trimmed();
        if (key == "include" && value == "registry")
            config.includeRegistry = true;
        sections[section][key] = value;
    }
    if (sections.contains("global")) {
        auto global = sections.take("global");
        config.global.workgroup = global.take("workgroup");
        if (config.global.workgroup.isEmpty())
            config.global.workgroup = "WORKGROUP";
        config.global.serverString = global.take("server string");
        config.global.logLevel = global.take("log level");
        config.global.macos = vfsList(global.value("vfs objects")).contains("fruit");
        dropDangerous(&global);
        config.global.extra = global;
        if (config.global.macos) {
            QStringList vfs = vfsList(config.global.extra.value("vfs objects"));
            vfs.removeAll("catia");
            vfs.removeAll("fruit");
            vfs.removeAll("streams_xattr");
            if (vfs.isEmpty())
                config.global.extra.remove("vfs objects");
            else
                config.global.extra["vfs objects"] = joinVfs(vfs);
            config.global.extra.remove("fruit:encoding");
            config.global.extra.remove("fruit:metadata");
        }
    }
    for (auto it = sections.cbegin(); it != sections.cend(); ++it) {
        if (it.key().compare("global", Qt::CaseInsensitive) == 0)
            continue;
        config.shares.append(shareFromParameters(it.key(), it.value()));
    }
    return config;
}

QString ensureSambaInclude(const QString &smbConf) {
    if (smbConf.contains("include = /etc/samba/shares.conf"))
        return smbConf;
    QString out;
    bool inserted = false;
    bool inGlobal = false;
    const auto lines = smbConf.split('\n');
    for (int i = 0; i < lines.size(); ++i) {
        const auto trimmed = lines.at(i).trimmed();
        if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
            if (inGlobal && !inserted) {
                out += "   include = /etc/samba/shares.conf\n";
                inserted = true;
            }
            inGlobal = trimmed.compare("[global]", Qt::CaseInsensitive) == 0;
        }
        out += lines.at(i) + "\n";
    }
    if (!inserted) {
        if (!inGlobal)
            out += "\n[global]\n";
        out += "   include = /etc/samba/shares.conf\n";
    }
    return out;
}

QString stripSambaShares(const QString &smbConf) {
    // A section with a real folder moves to shares.conf. [homes] on Debian
    // has no path, and that section stays here instead of failing the save.
    QString out;
    QString buffered;
    QString sectionPath;
    bool buffering = false;
    auto flush = [&]() {
        if (!buffering)
            return;
        if (!absolutePathOk(sectionPath))
            out += buffered;
        buffered.clear();
        sectionPath.clear();
        buffering = false;
    };
    for (const auto &line : smbConf.split('\n')) {
        const auto trimmed = line.trimmed();
        if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
            flush();
            if (trimmed.compare("[global]", Qt::CaseInsensitive) == 0) {
                out += line + "\n";
                continue;
            }
            buffering = true;
            buffered = line + "\n";
            continue;
        }
        if (buffering) {
            buffered += line + "\n";
            if (trimmed.isEmpty() || trimmed.startsWith('#') || trimmed.startsWith(';'))
                continue;
            const auto eq = trimmed.indexOf('=');
            if (eq > 0 && trimmed.left(eq).trimmed().compare("path", Qt::CaseInsensitive) == 0)
                sectionPath = trimmed.mid(eq + 1).trimmed();
            continue;
        }
        out += line + "\n";
    }
    flush();
    return ensureSambaInclude(out);
}

QString nfsText(const QVector<NfsExport> &exports) {
    QString out;
    for (const auto &exp : exports) {
        if (!absolutePathOk(exp.path) || exp.clients.isEmpty())
            continue;
        QStringList clients;
        for (const auto &client : exp.clients) {
            if (!nfsHostOk(client.host) || !nfsOptionsOk(client.options))
                continue;
            clients << client.host + "(" + client.options + ")";
        }
        if (clients.isEmpty())
            continue;
        out += (exp.enabled ? "" : "# ") + exp.path + " " + clients.join(' ') + "\n";
    }
    return out;
}

QVector<NfsExport> parseNfs(const QString &text) {
    QVector<NfsExport> exports;
    for (auto line : text.split('\n')) {
        auto trimmed = line.trimmed();
        if (trimmed.isEmpty())
            continue;
        bool enabled = true;
        if (trimmed.startsWith('#')) {
            enabled = false;
            trimmed = trimmed.mid(1).trimmed();
            if (trimmed.isEmpty() || trimmed.startsWith('#'))
                continue;
        }
        QString path;
        QString rest;
        if (trimmed.startsWith('"')) {
            const auto end = trimmed.indexOf('"', 1);
            if (end < 0)
                continue;
            path = trimmed.mid(1, end - 1);
            rest = trimmed.mid(end + 1).trimmed();
        } else {
            const auto space = trimmed.indexOf(QRegularExpression("\\s+"));
            if (space < 0)
                continue;
            path = trimmed.left(space);
            rest = trimmed.mid(space).trimmed();
        }
        // A prose comment such as "to NFS clients. See exports(5)." is not an
        // export. A disabled export still has a folder path.
        if (!absolutePathOk(path))
            continue;
        NfsExport exp;
        exp.path = path;
        exp.enabled = enabled;
        static const QRegularExpression clientRe("(\\S+)\\(([^)]*)\\)");
        auto it = clientRe.globalMatch(rest);
        while (it.hasNext()) {
            const auto match = it.next();
            NfsClient client;
            client.host = match.captured(1);
            client.options = match.captured(2);
            exp.clients.append(client);
        }
        if (!exp.clients.isEmpty())
            exports.append(exp);
    }
    return exports;
}

QByteArray iscsiJson(const IscsiConfig &config) {
    QJsonObject root;
    root["clustered"] = config.clustered;
    root["pool"] = config.pool;
    QJsonArray devices;
    for (const auto &device : config.devices) {
        devices.append(QJsonObject{{"name", device.name},
                                   {"kind", device.kind},
                                   {"path", device.path},
                                   {"size", device.size},
                                   {"enabled", device.enabled},
                                   {"writeProtected", device.writeProtected}});
    }
    QJsonArray targets;
    for (const auto &target : config.targets) {
        QJsonArray portals;
        for (const auto &portal : target.portals)
            portals.append(QJsonObject{{"address", portal.address}, {"port", portal.port}});
        QJsonArray acls;
        for (const auto &acl : target.acls)
            acls.append(QJsonObject{{"initiator", acl.initiator}, {"userid", acl.userid}, {"password", acl.password}});
        targets.append(QJsonObject{{"iqn", target.iqn},
                                   {"enabled", target.enabled},
                                   {"device", target.device},
                                   {"portals", portals},
                                   {"acls", acls}});
    }
    root["devices"] = devices;
    root["targets"] = targets;
    return QJsonDocument(root).toJson(QJsonDocument::Indented);
}

IscsiConfig parseIscsiJson(const QByteArray &json, bool *ok) {
    IscsiConfig config;
    QJsonParseError error;
    const auto doc = QJsonDocument::fromJson(json, &error);
    if (ok)
        *ok = error.error == QJsonParseError::NoError && doc.isObject();
    if (!doc.isObject())
        return config;
    const auto root = doc.object();
    config.clustered = root.value("clustered").toBool();
    config.pool = root.value("pool").toString("rbd");
    for (const auto &value : root.value("devices").toArray()) {
        const auto obj = value.toObject();
        IscsiDevice device;
        device.name = obj.value("name").toString();
        device.kind = obj.value("kind").toString("fileio");
        device.path = obj.value("path").toString();
        device.size = obj.value("size").toString();
        device.enabled = obj.value("enabled").toBool(true);
        device.writeProtected = obj.value("writeProtected").toBool(false);
        if (shareNameOk(device.name))
            config.devices.append(device);
    }
    for (const auto &value : root.value("targets").toArray()) {
        const auto obj = value.toObject();
        IscsiTarget target;
        target.iqn = obj.value("iqn").toString();
        target.enabled = obj.value("enabled").toBool(true);
        target.device = obj.value("device").toString();
        for (const auto &portalValue : obj.value("portals").toArray()) {
            const auto portalObj = portalValue.toObject();
            IscsiPortal portal;
            portal.address = portalObj.value("address").toString("0.0.0.0");
            portal.port = portalObj.value("port").toString("3260");
            target.portals.append(portal);
        }
        for (const auto &aclValue : obj.value("acls").toArray()) {
            const auto aclObj = aclValue.toObject();
            IscsiAcl acl;
            acl.initiator = aclObj.value("initiator").toString();
            acl.userid = aclObj.value("userid").toString();
            acl.password = aclObj.value("password").toString();
            if (!acl.initiator.isEmpty())
                target.acls.append(acl);
        }
        if (target.iqn.startsWith("iqn."))
            config.targets.append(target);
    }
    return config;
}

QVector<IssuedCommand> iscsiApplyCommands(const IscsiConfig &config) {
    QVector<IssuedCommand> commands;
    const auto tool = config.clustered ? QString("gwcli") : QString("targetcli");
    auto add = [&commands](const QStringList &args, const QString &input = {}) { commands.append({args, input}); };
    for (const auto &device : config.devices) {
        if (!shareNameOk(device.name) || !absolutePathOk(device.path))
            continue;
        const auto size = device.size.isEmpty() ? QString("1G") : device.size;
        if (config.clustered) {
            add({"rbd", "create", config.pool + "/" + device.name, "--size", size});
        } else if (device.kind == "block") {
            add({"targetcli", "/backstores/block", "create", device.name, device.path});
        } else {
            add({"targetcli", "/backstores/fileio", "create", device.name, device.path, size});
            if (device.writeProtected)
                add({"targetcli", "/backstores/fileio/" + device.name, "set", "attribute", "write_protect=1"});
        }
    }
    for (const auto &target : config.targets) {
        if (!target.iqn.startsWith("iqn.") || target.iqn.contains(' ') || target.iqn.contains(QStringLiteral("..")))
            continue;
        add({tool, "/iscsi", "create", target.iqn});
        if (!target.device.isEmpty() && shareNameOk(target.device)) {
            QString kind = "fileio";
            for (const auto &device : config.devices) {
                if (device.name == target.device)
                    kind = device.kind;
            }
            const auto store = config.clustered ? target.device
                               : kind == "block" ? QString("/backstores/block/%1").arg(target.device)
                                                 : QString("/backstores/fileio/%1").arg(target.device);
            add({tool, "/iscsi/" + target.iqn + "/tpg1/luns", "create", store});
        }
        for (const auto &portal : target.portals) {
            if (!nfsHostOk(portal.address) || !portOk(portal.port))
                continue;
            add({tool, "/iscsi/" + target.iqn + "/tpg1/portals", "create", portal.address, portal.port});
        }
        for (const auto &acl : target.acls) {
            if (acl.initiator.isEmpty() || acl.initiator.contains(' ') || acl.initiator.contains(QStringLiteral("..")))
                continue;
            add({tool, "/iscsi/" + target.iqn + "/tpg1/acls", "create", acl.initiator});
            if (!acl.userid.isEmpty())
                add({tool, "/iscsi/" + target.iqn + "/tpg1/acls/" + acl.initiator, "set", "auth", "userid=" + acl.userid});
            if (!acl.password.isEmpty())
                add({tool},
                    QString("/iscsi/%1/tpg1/acls/%2 set auth password=%3\n").arg(target.iqn, acl.initiator, acl.password));
        }
        add({tool, "/iscsi/" + target.iqn + "/tpg1", target.enabled ? "enable" : "disable"});
    }
    // An empty config has nothing to persist. Calling saveconfig anyway makes
    // every Samba or NFS save fail on a machine without targetcli-fb.
    if (!config.clustered && (!config.devices.isEmpty() || !config.targets.isEmpty()))
        add({"targetcli", "saveconfig"});
    return commands;
}

namespace {

QJsonObject mapToJson(const QMap<QString, QString> &map) {
    QJsonObject object;
    for (auto it = map.cbegin(); it != map.cend(); ++it)
        object.insert(it.key(), it.value());
    return object;
}

QMap<QString, QString> mapFromJson(const QJsonObject &object) {
    QMap<QString, QString> map;
    for (const auto &key : object.keys()) {
        if (object.value(key).isString())
            map.insert(key, object.value(key).toString());
    }
    dropDangerous(&map);
    return map;
}

QJsonObject shareToJson(const SambaShare &share) {
    return QJsonObject{{"name", share.name},
                       {"path", share.path},
                       {"comment", share.comment},
                       {"enabled", share.enabled},
                       {"guest", share.guest},
                       {"readOnly", share.readOnly},
                       {"browsable", share.browsable},
                       {"inheritPermissions", share.inheritPermissions},
                       {"windowsAcls", share.windowsAcls},
                       {"shadowCopy", share.shadowCopy},
                       {"shadowKind", share.shadowKind},
                       {"macos", share.macos},
                       {"audit", share.audit},
                       {"validUsers", share.validUsers},
                       {"directoryMode", share.directoryMode},
                       {"createPath", share.createPath},
                       {"quota", share.quota},
                       {"layoutPool", share.layoutPool},
                       {"cephRemount", share.cephRemount},
                       {"extra", mapToJson(share.extra)}};
}

SambaShare shareFromJson(const QJsonObject &object) {
    SambaShare share;
    share.name = object.value("name").toString();
    share.path = object.value("path").toString();
    share.comment = object.value("comment").toString();
    share.enabled = object.value("enabled").toBool(true);
    share.guest = object.value("guest").toBool(false);
    share.readOnly = object.value("readOnly").toBool(false);
    share.browsable = object.value("browsable").toBool(true);
    share.inheritPermissions = object.value("inheritPermissions").toBool(false);
    share.windowsAcls = object.value("windowsAcls").toBool(false);
    share.shadowCopy = object.value("shadowCopy").toBool(false);
    share.shadowKind = object.value("shadowKind").toString("zfs");
    share.macos = object.value("macos").toBool(false);
    share.audit = object.value("audit").toBool(false);
    share.validUsers = object.value("validUsers").toString();
    share.directoryMode = object.value("directoryMode").toString();
    share.createPath = object.value("createPath").toBool(false);
    share.quota = object.value("quota").toString();
    share.layoutPool = object.value("layoutPool").toString();
    share.cephRemount = object.value("cephRemount").toBool(false);
    share.extra = mapFromJson(object.value("extra").toObject());
    return share;
}

} // namespace

QJsonObject sambaToJson(const SambaConfig &config) {
    QJsonArray shares;
    for (const auto &share : config.shares)
        shares.append(shareToJson(share));
    return QJsonObject{{"global", QJsonObject{{"workgroup", config.global.workgroup},
                                              {"serverString", config.global.serverString},
                                              {"logLevel", config.global.logLevel},
                                              {"macos", config.global.macos},
                                              {"extra", mapToJson(config.global.extra)}}},
                       {"shares", shares}};
}

SambaConfig sambaFromJson(const QJsonObject &object, bool *ok) {
    SambaConfig config;
    const auto global = object.value("global").toObject();
    if (ok)
        *ok = object.contains("shares") && object.value("shares").isArray();
    config.global.workgroup = global.value("workgroup").toString("WORKGROUP");
    config.global.serverString = global.value("serverString").toString();
    config.global.logLevel = global.value("logLevel").toString("0");
    config.global.macos = global.value("macos").toBool(false);
    config.global.extra = mapFromJson(global.value("extra").toObject());
    for (const auto &value : object.value("shares").toArray())
        config.shares.append(shareFromJson(value.toObject()));
    return config;
}

QJsonArray nfsToJson(const QVector<NfsExport> &exports) {
    QJsonArray array;
    for (const auto &exp : exports) {
        QJsonArray clients;
        for (const auto &client : exp.clients)
            clients.append(QJsonObject{{"host", client.host}, {"options", client.options}});
        array.append(QJsonObject{{"path", exp.path}, {"enabled", exp.enabled}, {"clients", clients}});
    }
    return array;
}

QVector<NfsExport> nfsFromJson(const QJsonArray &array) {
    QVector<NfsExport> exports;
    for (const auto &value : array) {
        const auto object = value.toObject();
        NfsExport exp;
        exp.path = object.value("path").toString();
        exp.enabled = object.value("enabled").toBool(true);
        for (const auto &clientValue : object.value("clients").toArray()) {
            const auto client = clientValue.toObject();
            exp.clients.append({client.value("host").toString(), client.value("options").toString("rw,sync,no_subtree_check")});
        }
        if (absolutePathOk(exp.path) && !exp.clients.isEmpty())
            exports.append(exp);
    }
    return exports;
}
