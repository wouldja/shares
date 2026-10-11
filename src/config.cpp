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

bool commandAllowed(const QStringList &args) {
    if (args.isEmpty())
        return false;
    static const QRegularExpression token("^[A-Za-z0-9_./:=+@,%|-]+$");
    for (const auto &arg : args) {
        if (arg.isEmpty() || arg.contains("..") || !token.match(arg).hasMatch())
            return false;
    }
    const auto program = args.first();
    if (program == "exportfs")
        return args == QStringList{"exportfs", "-ra"};
    if (program == "systemctl") {
        if (args.size() != 3)
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
            return accountNameOk(args.at(2));
        return false;
    }
    if (program == "pdbedit")
        return args == QStringList{"pdbedit", "-L"};
    if (program == "targetcli" || program == "gwcli" || program == "rbd" || program == "mc" || program == "garage"
        || program == "radosgw-admin")
        return args.size() >= 2 && args.size() <= 12;
    if (program == "mkdir")
        return args.size() == 3 && args.at(1) == "-p" && absolutePathOk(args.at(2));
    if (program == "chmod") {
        static const QRegularExpression mode("^0[0-7]{3}$");
        return args.size() == 3 && mode.match(args.at(1)).hasMatch() && absolutePathOk(args.at(2));
    }
    // RustFS has no local admin tool. Curl is allowed only against the
    // loopback admin API, never an arbitrary URL. A one-digit connect and
    // total timeout is optional so a dead endpoint cannot hang a save.
    if (program == "curl") {
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
        return rustfs.match(args.at(index)).hasMatch();
    }
    return false;
}

static QMap<QString, QString> shareParameters(const SambaShare &share) {
    QMap<QString, QString> params = share.extra;
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
    QString out;
    bool skipping = false;
    for (const auto &line : smbConf.split('\n')) {
        const auto trimmed = line.trimmed();
        if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
            skipping = trimmed.compare("[global]", Qt::CaseInsensitive) != 0;
            if (skipping)
                continue;
        }
        if (!skipping)
            out += line + "\n";
    }
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

QStringList iscsiApplyCommands(const IscsiConfig &config) {
    QStringList commands;
    const auto tool = config.clustered ? QString("gwcli") : QString("targetcli");
    for (const auto &device : config.devices) {
        if (!shareNameOk(device.name) || !absolutePathOk(device.path))
            continue;
        if (config.clustered) {
            const auto size = device.size.isEmpty() ? QString("1G") : device.size;
            commands << QString("rbd create %1/%2 --size %3").arg(config.pool, device.name, size);
        } else if (device.kind == "block") {
            commands << QString("targetcli /backstores/block create %1 %2").arg(device.name, device.path);
        } else {
            const auto size = device.size.isEmpty() ? QString("1G") : device.size;
            commands << QString("targetcli /backstores/fileio create %1 %2 %3").arg(device.name, device.path, size);
            if (device.writeProtected)
                commands << QString("targetcli /backstores/fileio/%1 set attribute write_protect=1").arg(device.name);
        }
    }
    for (const auto &target : config.targets) {
        if (!target.iqn.startsWith("iqn.") || target.iqn.contains(' '))
            continue;
        commands << tool + " /iscsi create " + target.iqn;
        if (!target.device.isEmpty() && shareNameOk(target.device)) {
            QString kind = "fileio";
            for (const auto &device : config.devices) {
                if (device.name == target.device)
                    kind = device.kind;
            }
            const auto store = config.clustered ? target.device
                               : kind == "block" ? QString("/backstores/block/%1").arg(target.device)
                                                 : QString("/backstores/fileio/%1").arg(target.device);
            commands << QString("%1 /iscsi/%2/tpg1/luns create %3").arg(tool, target.iqn, store);
        }
        for (const auto &portal : target.portals) {
            if (!nfsHostOk(portal.address))
                continue;
            commands << QString("%1 /iscsi/%2/tpg1/portals create %3 %4").arg(tool, target.iqn, portal.address, portal.port);
        }
        for (const auto &acl : target.acls) {
            if (acl.initiator.isEmpty() || acl.initiator.contains(' '))
                continue;
            commands << QString("%1 /iscsi/%2/tpg1/acls create %3").arg(tool, target.iqn, acl.initiator);
            if (!acl.userid.isEmpty())
                commands << QString("%1 /iscsi/%2/tpg1/acls/%3 set auth userid=%4")
                                .arg(tool, target.iqn, acl.initiator, acl.userid);
            if (!acl.password.isEmpty())
                commands << QString("%1 /iscsi/%2/tpg1/acls/%3 set auth password=%4")
                                .arg(tool, target.iqn, acl.initiator, acl.password);
        }
        commands << QString("%1 /iscsi/%2/tpg1 %3").arg(tool, target.iqn, target.enabled ? "enable" : "disable");
    }
    // An empty config has nothing to persist. Calling saveconfig anyway makes
    // every Samba or NFS save fail on a machine without targetcli-fb.
    if (!config.clustered && (!config.devices.isEmpty() || !config.targets.isEmpty()))
        commands << "targetcli saveconfig";
    return commands;
}
