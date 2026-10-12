#include "store.h"

#include <QHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSet>
#include <QStandardPaths>
#include <QThread>

#include <vector>

namespace {

const QStringList kFiles = {"etc/samba/shares.conf", "etc/samba/smb.conf", "etc/samba/smb.conf.bak",
                            "etc/exports.d/shares.exports", "etc/shares/iscsi.json", "etc/shares/s3.json"};

QString readFile(const QString &path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return {};
    return QString::fromUtf8(file.readAll());
}

QString serviceState(const CommandResult &result, const QString &unit, const QString &package) {
    if (result.missing)
        return package + " is not installed";
    const auto state = result.out.trimmed();
    if (state.isEmpty())
        return unit + " is " + (result.err.trimmed().isEmpty() ? QString("unknown") : result.err.trimmed());
    return unit + " is " + state;
}

QHash<QString, CommandResult> runProbes(Commands *commands, const QVector<ProbeRequest> &probes) {
    QHash<QString, CommandResult> out;
    if (!commands || probes.isEmpty())
        return out;
    // One remote shell for the whole list. A single probe, and every local
    // probe, still runs on its own.
    if (commands->batchProbes() && probes.size() > 1)
        return commands->runBatch(probes);
    if (!commands->parallelProbes() || probes.size() == 1) {
        for (const auto &probe : probes)
            out.insert(probe.id, commands->run(probe.program, probe.args, {}, probe.timeoutMs));
        return out;
    }
    // QProcess needs a QThread. Each probe gets one, and this call waits until
    // they finish. A separate thread per probe keeps a slow curl from holding
    // up systemctl.
    std::vector<CommandResult> results(probes.size());
    QVector<QThread *> threads;
    threads.reserve(probes.size());
    for (int i = 0; i < probes.size(); ++i) {
        const auto probe = probes.at(i);
        auto *thread = QThread::create([commands, probe, i, &results] {
            results[i] = commands->run(probe.program, probe.args, {}, probe.timeoutMs);
        });
        thread->start();
        threads.append(thread);
    }
    for (auto *thread : threads) {
        thread->wait();
        delete thread;
    }
    for (int i = 0; i < probes.size(); ++i)
        out.insert(probes.at(i).id, results.at(i));
    return out;
}

QStringList rustfsCurl(const QString &method, const QString &url) {
    QStringList args{"curl", "-sf", "--connect-timeout", "2", "--max-time", "3"};
    if (!method.isEmpty())
        args << "-X" << method;
    args << url;
    return args;
}

QStringList tailnetName(const QString &json) {
    const auto doc = QJsonDocument::fromJson(json.toUtf8());
    const auto name = doc.object().value("Self").toObject().value("DNSName").toString();
    if (name.isEmpty())
        return {};
    auto trimmed = name;
    while (trimmed.endsWith('.'))
        trimmed.chop(1);
    return {trimmed};
}

} // namespace

bool loopbackOrigin(const QString &url) {
    static const QRegularExpression re("^http://127\\.0\\.0\\.1:[0-9]{2,5}$");
    return re.match(url).hasMatch();
}

Commands::~Commands() = default;

QHash<QString, CommandResult> Commands::runBatch(const QVector<ProbeRequest> &probes) {
    QHash<QString, CommandResult> out;
    for (const auto &probe : probes)
        out.insert(probe.id, run(probe.program, probe.args, {}, probe.timeoutMs));
    return out;
}

CommandResult Commands::run(const QString &program, const QStringList &args, const QString &input, int timeoutMs) {
    if (QStandardPaths::findExecutable(program).isEmpty())
        return {127, {}, "not found", true};
    QProcess process;
    process.start(program, args);
    if (!process.waitForStarted(qMin(3000, timeoutMs)))
        return {127, {}, process.errorString(), true};
    if (!input.isEmpty())
        process.write(input.toUtf8());
    process.closeWriteChannel();
    if (!process.waitForFinished(timeoutMs)) {
        process.kill();
        process.waitForFinished(1000);
        return {124, {}, "timed out", false};
    }
    return {process.exitCode(), QString::fromUtf8(process.readAllStandardOutput()),
            QString::fromUtf8(process.readAllStandardError()), false};
}

Library::Library(QString root, Commands *commands) : m_root(std::move(root)), m_commands(commands) {
    setRoot(m_root);
}

void Library::setRoot(QString root) {
    if (root.endsWith('/') && root.size() > 1)
        root.chop(1);
    m_root = root;
}

void Library::loadFiles() {
    notice.clear();
    const auto sharesConf = readFile(m_root + "/etc/samba/shares.conf");
    const auto smbConf = readFile(m_root + "/etc/samba/smb.conf");
    auto fromShares = parseSamba(sharesConf);
    auto fromSmb = parseSamba(smbConf);
    samba.global = fromSmb.global.workgroup.isEmpty() ? fromShares.global : fromSmb.global;
    if (!fromShares.global.workgroup.isEmpty() && fromShares.global.workgroup != "WORKGROUP")
        samba.global = fromShares.global;
    else if (!fromSmb.global.workgroup.isEmpty())
        samba.global = fromSmb.global;
    samba.includeRegistry = fromSmb.includeRegistry;
    // [homes] on Debian has no folder. It stays in smb.conf and is not a row,
    // so Save is not asked to invent a path for it.
    auto withFolder = [](const QVector<SambaShare> &shares) {
        QVector<SambaShare> kept;
        for (const auto &share : shares) {
            if (absolutePathOk(share.path))
                kept.append(share);
        }
        return kept;
    };
    if (!fromShares.shares.isEmpty())
        samba.shares = withFolder(fromShares.shares);
    else
        samba.shares = withFolder(fromSmb.shares);
    smbHadShares = false;
    for (const auto &share : fromSmb.shares) {
        if (absolutePathOk(share.path))
            smbHadShares = true;
    }
    if (!fromShares.shares.isEmpty() && smbHadShares)
        notice = "Samba shares are in both smb.conf and shares.conf. Save keeps the shares.conf copy and backs up smb.conf.";
    else if (smbHadShares)
        notice = "Save moves Samba shares from smb.conf into shares.conf and keeps smb.conf.bak.";

    QString exports;
    const QDir exportsDir(m_root + "/etc/exports.d");
    const auto files = exportsDir.entryList({"*.exports"}, QDir::Files, QDir::Name);
    for (const auto &name : files)
        exports += readFile(exportsDir.filePath(name));
    exports += readFile(m_root + "/etc/exports");
    nfs = parseNfs(exports);

    bool iscsiOk = false;
    iscsi = parseIscsiJson(readFile(m_root + "/etc/shares/iscsi.json").toUtf8(), &iscsiOk);

    const auto s3Json = QJsonDocument::fromJson(readFile(m_root + "/etc/shares/s3.json").toUtf8()).object();
    const auto origin = s3Json.value("rustfs").toString();
    if (loopbackOrigin(origin))
        rustfsEndpoint = origin;
}

void Library::loadStatus() {
    if (!m_commands)
        return;
    const int timeout = m_commands->probeTimeoutMs();
    QVector<ProbeRequest> probes = {
        {"samba", "systemctl", {"is-active", m_profile.sambaUnit}, timeout},
        {"nfs", "systemctl", {"is-active", m_profile.nfsUnit}, timeout},
        {"iscsi", "systemctl", {"is-active", m_profile.iscsiUnit}, timeout},
        {"gwcli", "gwcli", {"--version"}, timeout},
        {"rbd", "rbd", {"--version"}, timeout},
        {"hostname-s", "hostname", {"-s"}, timeout},
        {"hostname-f", "hostname", {"-f"}, timeout},
        {"tailscale", "tailscale", {"status", "--json"}, qMax(timeout, 3000)},
        {"passwd", "getent", {"passwd"}, timeout},
        {"pdbedit", "pdbedit", {"-L"}, timeout},
    };
    const auto result = runProbes(m_commands, probes);
    sambaState = serviceState(result.value("samba"), m_profile.sambaUnit, m_profile.sambaPackage);
    nfsState = serviceState(result.value("nfs"), m_profile.nfsUnit, m_profile.nfsPackage);
    iscsiState = serviceState(result.value("iscsi"), m_profile.iscsiUnit, m_profile.iscsiPackage);
    if (result.value("gwcli").missing && result.value("rbd").missing)
        iscsiState += iscsi.clustered ? " · clustered tools are not installed" : "";
    else if (iscsi.clustered)
        iscsiState += " · clustered tools are installed";

    users.clear();
    QSet<QString> sambaUsers;
    for (const auto &line : result.value("pdbedit").out.split('\n')) {
        const auto name = line.section(':', 0, 0).trimmed();
        if (accountNameOk(name))
            sambaUsers.insert(name);
    }
    for (const auto &line : result.value("passwd").out.split('\n')) {
        const auto parts = line.split(':');
        if (parts.size() < 3 || !accountNameOk(parts.at(0)))
            continue;
        bool ok = false;
        const int uid = parts.at(2).toInt(&ok);
        if (!ok || uid < 1000)
            continue;
        users.append({parts.at(0), sambaUsers.contains(parts.at(0))});
    }

    reachable.clear();
    const auto shortName = result.value("hostname-s").out.trimmed();
    const auto fullName = result.value("hostname-f").out.trimmed();
    if (!shortName.isEmpty())
        reachable << shortName + ".local";
    if (!fullName.isEmpty() && fullName != shortName)
        reachable << fullName;
    const auto tailscale = result.value("tailscale");
    tailscaleStatus = (!tailscale.missing && tailscale.code == 0) ? tailscale.out : QString();
    if (!tailscaleStatus.isEmpty())
        reachable += tailnetName(tailscaleStatus);
    if (reachable.isEmpty())
        reachable << "localhost";
}

void Library::loadS3() {
    if (!m_commands)
        return;
    const int timeout = m_commands->probeTimeoutMs();
    const int curlTimeout = qMax(timeout, 4000);
    const auto bucketsUrl = rustfsEndpoint + "/rustfs/admin/v3/buckets";
    const auto curl = rustfsCurl({}, bucketsUrl);
    // Detection and the bucket lists share one probe list, so a remote computer
    // answers in one shell instead of a second wave after the first returns.
    QVector<ProbeRequest> probes = {
        {"minio-unit", "systemctl", {"is-active", "minio"}, timeout},
        {"garage-unit", "systemctl", {"is-active", "garage"}, timeout},
        {"ceph-unit", "systemctl", {"is-active", "ceph-radosgw"}, timeout},
        {"rustfs-unit", "systemctl", {"is-active", "rustfs"}, timeout},
        {"mc", "mc", {"--version"}, timeout},
        {"garage", "garage", {"--version"}, timeout},
        {"radosgw-admin", "radosgw-admin", {"--version"}, timeout},
        {"rustfs-curl", curl.first(), curl.mid(1), curlTimeout},
        {"minio-buckets", "mc", {"ls", "local"}, timeout},
        {"minio-access", "mc", {"admin", "user", "list", "local"}, timeout},
        {"garage-buckets", "garage", {"bucket", "list"}, timeout},
        {"garage-access", "garage", {"key", "list"}, timeout},
        {"ceph-buckets", "radosgw-admin", {"bucket", "list"}, timeout},
        {"ceph-access", "radosgw-admin", {"user", "list"}, timeout},
    };
    const auto result = runProbes(m_commands, probes);
    const auto toolReady = [&result](const QString &id) {
        const auto version = result.value(id);
        return !version.missing && version.code == 0 && !version.out.trimmed().isEmpty();
    };
    const auto unitActive = [&result](const QString &id) { return result.value(id).out.trimmed() == "active"; };
    s3Backends.clear();
    // Curl existing is not RustFS existing. RustFS counts when its service is
    // up or its loopback admin API answers.
    if (unitActive("minio-unit") || toolReady("mc"))
        s3Backends << "minio";
    if (unitActive("garage-unit") || toolReady("garage"))
        s3Backends << "garage";
    if (unitActive("ceph-unit") || toolReady("radosgw-admin"))
        s3Backends << "ceph";
    const auto rustfsProbe = result.value("rustfs-curl");
    if (unitActive("rustfs-unit") || (!rustfsProbe.missing && rustfsProbe.code == 0 && !rustfsProbe.out.trimmed().isEmpty()))
        s3Backends << "rustfs";
    s3State = s3Backends.isEmpty() ? "no S3 backend is installed" : s3Backends.join(", ");
    s3 = {};
    for (const auto &backend : s3Backends) {
        CommandResult buckets;
        if (backend == "rustfs")
            buckets = rustfsProbe;
        else
            buckets = result.value(backend + "-buckets");
        if (!buckets.missing && buckets.code == 0)
            s3.buckets += parseBucketList(backend, buckets.out);
        else if (!buckets.missing && !buckets.err.trimmed().isEmpty()) {
            const auto line = backend + ": " + buckets.err.trimmed();
            if (!notice.contains(line))
                notice += (notice.isEmpty() ? "" : " ") + line;
        }
        if (backend == "rustfs")
            continue;
        const auto access = result.value(backend + "-access");
        if (!access.missing && access.code == 0) {
            for (const auto &name : parseAccessList(backend, access.out))
                s3.access.append({backend, name, backend == "garage" ? "key" : "user"});
        }
    }
}

void Library::loadSessions(int protocol) {
    if (!m_commands)
        return;
    const int timeout = m_commands->probeTimeoutMs();
    if (protocol == 0) {
        const auto smbstatus = m_commands->run("smbstatus", {"-b"}, {}, timeout);
        sambaSessions = parseSessions(smbstatus.out);
    } else if (protocol == 1) {
        const auto nfsClients = m_commands->run("ss", {"-H", "-t", "state", "established", "sport", "=", ":2049"}, {}, timeout);
        nfsSessions = parseSessions(nfsClients.missing ? QString() : nfsClients.out);
    } else if (protocol == 2) {
        const auto targetSessions = m_commands->run("targetcli", {"sessions"}, {}, timeout);
        iscsiSessions = parseSessions(targetSessions.out);
    }
}

Plan Library::plan(const SambaConfig &nextSamba, const QVector<NfsExport> &nextNfs, const IscsiConfig &nextIscsi) const {
    Plan plan;
    if (iscsi.clustered != nextIscsi.clustered && (!nextIscsi.targets.isEmpty() || !nextIscsi.devices.isEmpty())) {
        plan.error = "Switch clustered mode only when no targets are listed. Remove them, then switch.";
        return plan;
    }
    for (const auto &share : nextSamba.shares) {
        if (!shareNameOk(share.name)) {
            plan.error = "Share names use letters, numbers, and . _ $ -.";
            return plan;
        }
        if (!absolutePathOk(share.path)) {
            plan.error = "A share path has to be an absolute path.";
            return plan;
        }
        if (!share.directoryMode.isEmpty()) {
            static const QRegularExpression mode("^0[0-7]{3}$");
            if (!mode.match(share.directoryMode).hasMatch()) {
                plan.error = "Directory mode looks like 0755.";
                return plan;
            }
        }
        if (share.extra.contains("include")) {
            plan.error = "An advanced key cannot include another file.";
            return plan;
        }
    }
    for (const auto &exp : nextNfs) {
        if (!absolutePathOk(exp.path)) {
            plan.error = "An export path has to be an absolute path.";
            return plan;
        }
        for (const auto &client : exp.clients) {
            if (!nfsHostOk(client.host) || !nfsOptionsOk(client.options)) {
                plan.error = "An NFS client or its options use a character Shares will not write.";
                return plan;
            }
        }
    }
    if (!loopbackOrigin(rustfsEndpoint)) {
        plan.error = "The RustFS address has to be http://127.0.0.1 and a port.";
        return plan;
    }
    plan.files.append({"etc/samba/shares.conf", sambaShareText(nextSamba.global, nextSamba.shares)});
    const auto currentSmb = readFile(m_root + "/etc/samba/smb.conf");
    // Share sections that still live in smb.conf are moved, not copied, so
    // Samba does not publish the same name twice. The previous file is kept.
    if (!parseSamba(currentSmb).shares.isEmpty()) {
        plan.files.append({"etc/samba/smb.conf.bak", currentSmb});
        plan.files.append({"etc/samba/smb.conf", stripSambaShares(currentSmb)});
    } else {
        plan.files.append({"etc/samba/smb.conf", ensureSambaInclude(currentSmb)});
    }
    plan.files.append({"etc/exports.d/shares.exports", nfsText(nextNfs)});
    plan.files.append({"etc/shares/iscsi.json", QString::fromUtf8(iscsiJson(nextIscsi))});
    plan.files.append({"etc/shares/s3.json", QString("{\n    \"rustfs\": \"%1\"\n}\n").arg(rustfsEndpoint)});
    for (const auto &share : nextSamba.shares) {
        if (share.createPath) {
            const QStringList args{"mkdir", "-p", share.path};
            if (!commandAllowed(args)) {
                plan.error = "That folder path cannot be created by Shares.";
                return plan;
            }
            plan.commands.append({args, {}});
        }
        if (!share.directoryMode.isEmpty()) {
            const QStringList args{"chmod", share.directoryMode, share.path};
            if (!commandAllowed(args)) {
                plan.error = "That folder mode cannot be applied by Shares.";
                return plan;
            }
            plan.commands.append({args, {}});
        }
    }
    const auto deleteTool = iscsi.clustered ? QString("gwcli") : QString("targetcli");
    QSet<QString> nextIqns;
    QSet<QString> nextDevices;
    for (const auto &target : nextIscsi.targets)
        nextIqns.insert(target.iqn);
    for (const auto &device : nextIscsi.devices)
        nextDevices.insert(device.name);
    for (const auto &target : iscsi.targets) {
        if (nextIqns.contains(target.iqn) || target.iqn.contains(' '))
            continue;
        const QStringList args = deleteTool.split(' ') + QStringList{"/iscsi", "delete", target.iqn};
        if (!commandAllowed(args)) {
            plan.error = "An iSCSI setting uses a character Shares will not send.";
            return plan;
        }
        plan.commands.append({args, {}});
    }
    for (const auto &device : iscsi.devices) {
        if (nextDevices.contains(device.name) || !shareNameOk(device.name))
            continue;
        // The backstore definition goes away. The image file or RBD volume stays.
        if (iscsi.clustered)
            continue;
        const auto kind = device.kind == "block" ? QString("block") : QString("fileio");
        const QStringList args{"targetcli", QString("/backstores/%1").arg(kind), "delete", device.name};
        if (!commandAllowed(args)) {
            plan.error = "An iSCSI setting uses a character Shares will not send.";
            return plan;
        }
        plan.commands.append({args, {}});
    }
    for (const auto &line : iscsiApplyCommands(nextIscsi)) {
        const auto args = line.split(' ', Qt::SkipEmptyParts);
        if (!commandAllowed(args)) {
            plan.error = "An iSCSI setting uses a character Shares will not send.";
            return plan;
        }
        plan.commands.append({args, {}});
    }
    // Deleting the last target does not go through iscsiApplyCommands, but the
    // deletion still has to be saved. Skip saveconfig when targetcli was never
    // invoked, so a share save does not require the iSCSI package.
    bool ranTargetcli = false;
    for (const auto &command : plan.commands) {
        if (!command.args.isEmpty() && command.args.first() == "targetcli")
            ranTargetcli = true;
    }
    if (ranTargetcli && plan.commands.last().args != QStringList{"targetcli", "saveconfig"})
        plan.commands.append({{"targetcli", "saveconfig"}, {}});
    const bool sambaWork = !nextSamba.shares.isEmpty() || !samba.shares.isEmpty() || smbHadShares;
    const bool nfsWork = !nextNfs.isEmpty() || !nfs.isEmpty();
    const bool iscsiWork = !nextIscsi.targets.isEmpty() || !nextIscsi.devices.isEmpty() || !iscsi.targets.isEmpty()
        || !iscsi.devices.isEmpty();
    if (sambaWork) {
        plan.commands.append({{"systemctl", "start", m_profile.sambaUnit}, {}});
        plan.commands.append({{"systemctl", "reload", m_profile.sambaUnit}, {}});
    }
    if (nfsWork) {
        plan.commands.append({{"systemctl", "start", m_profile.nfsUnit}, {}});
        plan.commands.append({{"exportfs", "-ra"}, {}});
    }
    if (iscsiWork && !nextIscsi.clustered) {
        plan.commands.append({{"systemctl", "start", m_profile.iscsiUnit}, {}});
        plan.commands.append({{"systemctl", "reload", m_profile.iscsiUnit}, {}});
    }
    return plan;
}

bool applyPlan(const QString &root, const Plan &plan, Commands *commands, QString *error, QString *output) {
    if (!plan.error.isEmpty()) {
        if (error)
            *error = plan.error;
        return false;
    }
    QString base = root;
    if (base.endsWith('/') && base.size() > 1)
        base.chop(1);
    for (const auto &file : plan.files) {
        if (!kFiles.contains(file.first) || file.first.contains("..")) {
            if (error)
                *error = "Refusing to write " + file.first;
            return false;
        }
        const auto dest = base + "/" + file.first;
        QDir().mkpath(QFileInfo(dest).absolutePath());
        QSaveFile out(dest);
        if (!out.open(QIODevice::WriteOnly)) {
            if (error)
                *error = "Could not write " + dest + ". " + out.errorString();
            return false;
        }
        // CHAP secrets live in the iSCSI record. Keep that file unreadable
        // by anyone but root.
        if (file.first.endsWith(".json"))
            out.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
        out.write(file.second.toUtf8());
        if (!out.commit()) {
            if (error)
                *error = "Could not commit " + dest;
            return false;
        }
    }
    if (!commands)
        return true;
    for (const auto &command : plan.commands) {
        if (!commandAllowed(command.args)) {
            if (error)
                *error = "Refusing to run " + command.args.join(' ');
            return false;
        }
        const auto result = commands->run(command.args.first(), command.args.mid(1), command.input);
        if (output && !result.out.isEmpty())
            output->append(result.out);
        if (result.missing) {
            if (error)
                *error = command.args.first() + " is not installed";
            return false;
        }
        if (result.code == 0)
            continue;
        const auto message = (result.err + " " + result.out).toLower();
        // Creating an object that is already there is the normal second save.
        const bool already = (command.args.first() == "targetcli" || command.args.first() == "gwcli" || command.args.first() == "rbd"
                              || command.args.first() == "mkdir")
            && message.contains("exist");
        if (already)
            continue;
        if (error)
            *error = result.err.trimmed().isEmpty() ? result.out.trimmed() : result.err.trimmed();
        if (error && error->isEmpty())
            *error = command.args.first() + " failed";
        return false;
    }
    return true;
}

QByteArray planToJson(const Plan &plan) {
    QJsonArray files;
    for (const auto &file : plan.files)
        files.append(QJsonObject{{"path", file.first}, {"body", file.second}});
    QJsonArray commands;
    for (const auto &command : plan.commands) {
        QJsonArray args;
        for (const auto &arg : command.args)
            args.append(arg);
        commands.append(QJsonObject{{"args", args}, {"input", command.input}});
    }
    return QJsonDocument(QJsonObject{{"files", files}, {"commands", commands}}).toJson(QJsonDocument::Compact);
}

Plan planFromJson(const QByteArray &bytes, bool *ok) {
    Plan plan;
    const auto doc = QJsonDocument::fromJson(bytes);
    if (!doc.isObject()) {
        if (ok)
            *ok = false;
        plan.error = "The request was not valid.";
        return plan;
    }
    for (const auto &value : doc.object().value("files").toArray()) {
        const auto obj = value.toObject();
        plan.files.append({obj.value("path").toString(), obj.value("body").toString()});
    }
    for (const auto &value : doc.object().value("commands").toArray()) {
        const auto obj = value.toObject();
        QStringList args;
        for (const auto &arg : obj.value("args").toArray())
            args << arg.toString();
        plan.commands.append({args, obj.value("input").toString()});
    }
    if (ok)
        *ok = true;
    return plan;
}

QStringList s3BucketArgs(const QString &backend, const QString &action, const QString &name, const QString &endpoint, QString *error) {
    if (!shareNameOk(name)) {
        if (error)
            *error = "Bucket names use letters, numbers, and . _ $ -.";
        return {};
    }
    if (backend == "minio" && action == "create")
        return {"mc", "mb", "local/" + name};
    if (backend == "minio" && action == "delete")
        return {"mc", "rb", "local/" + name};
    if (backend == "garage" && action == "create")
        return {"garage", "bucket", "create", name};
    if (backend == "garage" && action == "delete")
        return {"garage", "bucket", "delete", name};
    if (backend == "ceph" && action == "delete")
        return {"radosgw-admin", "bucket", "rm", "--bucket=" + name};
    if (backend == "ceph" && action == "create") {
        if (error)
            *error = "Ceph creates a bucket through the S3 API. This window can list buckets and remove an empty one.";
        return {};
    }
    if (backend == "rustfs" && loopbackOrigin(endpoint) && (action == "create" || action == "delete")) {
        const auto method = action == "create" ? QString("PUT") : QString("DELETE");
        return rustfsCurl(method, endpoint + "/rustfs/admin/v3/buckets/" + name);
    }
    if (error)
        *error = "That S3 backend is not available.";
    return {};
}

QStringList s3AccessArgs(const QString &backend, const QString &action, const QString &name, const QString &secret, QString *error) {
    if (!accountNameOk(name) && !shareNameOk(name)) {
        if (error)
            *error = "Access names use letters, numbers, and . _ -.";
        return {};
    }
    if (backend == "minio" && action == "create") {
        static const QRegularExpression token("^[A-Za-z0-9_./:=+@,%|-]+$");
        if (secret.isEmpty() || !token.match(secret).hasMatch()) {
            if (error)
                *error = "MinIO takes the password on the command line, so it cannot contain spaces or quotes.";
            return {};
        }
        return {"mc", "admin", "user", "add", "local", name, secret};
    }
    if (backend == "minio" && action == "delete")
        return {"mc", "admin", "user", "remove", "local", name};
    if (backend == "garage" && action == "create")
        return {"garage", "key", "create", name};
    if (backend == "garage" && action == "delete")
        return {"garage", "key", "delete", name};
    if (backend == "ceph" && action == "create")
        return {"radosgw-admin", "user", "create", "--uid=" + name, "--display-name=" + name};
    if (backend == "ceph" && action == "delete")
        return {"radosgw-admin", "user", "rm", "--uid=" + name};
    if (backend == "rustfs") {
        if (error)
            *error = "RustFS access keys are listed here. Create them with the RustFS admin API; this window does not store a secret key.";
        return {};
    }
    if (error)
        *error = "That S3 backend is not available.";
    return {};
}

QVector<S3Bucket> parseBucketList(const QString &backend, const QString &text) {
    QVector<S3Bucket> buckets;
    if (backend == "ceph" || backend == "rustfs") {
        const auto doc = QJsonDocument::fromJson(text.toUtf8());
        QJsonArray array = doc.isArray() ? doc.array() : doc.object().value("buckets").toArray();
        for (const auto &value : array) {
            const auto name = value.isString() ? value.toString() : value.toObject().value("name").toString(value.toObject().value("bucket").toString());
            if (!name.isEmpty())
                buckets.append({backend, name, {}});
        }
        return buckets;
    }
    for (const auto &line : text.split('\n')) {
        const auto trimmed = line.trimmed();
        if (trimmed.isEmpty() || trimmed.startsWith("ID") || trimmed.startsWith("Name"))
            continue;
        auto name = trimmed.section(' ', -1, -1).trimmed();
        if (name.endsWith('/'))
            name.chop(1);
        if (shareNameOk(name) || (!name.isEmpty() && !name.contains(' ')))
            buckets.append({backend, name, {}});
    }
    return buckets;
}

QStringList parseAccessList(const QString &backend, const QString &text) {
    QStringList names;
    if (backend == "ceph") {
        const auto doc = QJsonDocument::fromJson(text.toUtf8());
        const auto array = doc.isArray() ? doc.array() : doc.object().value("keys").toArray();
        for (const auto &value : array) {
            const auto name = value.isString() ? value.toString() : value.toObject().value("user").toString();
            if (!name.isEmpty())
                names << name;
        }
        return names;
    }
    for (const auto &line : text.split('\n')) {
        const auto name = line.trimmed().section(' ', 0, 0);
        if (accountNameOk(name) || (!name.isEmpty() && !name.contains(' ') && !name.endsWith(':')))
            names << name;
    }
    return names;
}

QStringList parseSessions(const QString &text) {
    QStringList sessions;
    for (const auto &line : text.split('\n')) {
        const auto trimmed = line.trimmed();
        if (trimmed.isEmpty() || trimmed.startsWith("PID") || trimmed.startsWith("Service") || trimmed.startsWith("---"))
            continue;
        sessions << trimmed;
    }
    return sessions;
}
