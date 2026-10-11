#include "remote.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMutexLocker>
#include <QProcess>
#include <QRegularExpression>
#include <QSaveFile>
#include <QStandardPaths>

namespace {

CommandResult runProcess(const QString &program, const QStringList &args, const QString &input, int timeoutMs) {
    if (QStandardPaths::findExecutable(program).isEmpty())
        return {127, {}, program + " is not installed", true};
    QProcess process;
    process.start(program, args);
    if (!process.waitForStarted(5000))
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

QString releaseValue(const QString &text, const QString &key) {
    static const QRegularExpression line("^([A-Z_]+)=(.*)$");
    for (const auto &raw : text.split('\n')) {
        const auto match = line.match(raw.trimmed());
        if (!match.hasMatch() || match.captured(1) != key)
            continue;
        auto value = match.captured(2).trimmed();
        if (value.startsWith('"') && value.endsWith('"') && value.size() >= 2)
            value = value.mid(1, value.size() - 2);
        return value;
    }
    return {};
}

bool toolExists(RemoteLink *link, const QStringList &paths) {
    for (const auto &path : paths) {
        if (link->exec({"test", "-x", path}, {}, 8000).code == 0)
            return true;
    }
    return false;
}

bool bundlePathOk(const QString &path) {
    static const QStringList fixed{"/etc/samba/shares.conf", "/etc/samba/smb.conf", "/etc/exports", "/etc/shares/iscsi.json",
                                   "/etc/shares/s3.json"};
    if (fixed.contains(path))
        return true;
    static const QRegularExpression exportPath("^/etc/exports\\.d/[A-Za-z0-9._-]+\\.exports$");
    return exportPath.match(path).hasMatch();
}

bool writeBundleFile(const QString &root, const QString &remotePath, const QByteArray &body, QString *error) {
    const auto localPath = root + remotePath;
    QDir().mkpath(QFileInfo(localPath).absolutePath());
    QSaveFile out(localPath);
    if (!out.open(QIODevice::WriteOnly)) {
        if (error)
            *error = "Could not store a copy of " + remotePath;
        return false;
    }
    out.write(body);
    if (!out.commit()) {
        if (error)
            *error = "Could not store a copy of " + remotePath;
        return false;
    }
    return true;
}

// Fixed script. No single quotes, so it can sit inside one remote shell argument.
// Each file is capped at 1 MiB. Missing files are skipped. A weird name is ignored
// on this side, so the remote glob cannot choose where bytes are written.
QString remoteBundleScript() {
    return QStringLiteral(
        "emit() {"
        " f=$1;"
        " if [ -f \"$f\" ]; then"
        " n=$(wc -c < \"$f\" | tr -d \" \");"
        " case \"$n\" in \"\"|*[!0-9]*) printf \"ERR %s\\n\" \"$f\"; return ;; esac;"
        " if [ \"$n\" -gt 1048576 ]; then printf \"SKIP %s\\n\" \"$f\"; return; fi;"
        " printf \"FILE %s %s\\n\" \"$f\" \"$n\";"
        " head -c \"$n\" \"$f\";"
        " printf \"\\n\";"
        " else printf \"MISS %s\\n\" \"$f\";"
        " fi;"
        "};"
        " emit /etc/samba/shares.conf;"
        " emit /etc/samba/smb.conf;"
        " emit /etc/exports;"
        " emit /etc/shares/iscsi.json;"
        " emit /etc/shares/s3.json;"
        " if [ -d /etc/exports.d ]; then"
        " for f in /etc/exports.d/*.exports; do"
        " if [ -f \"$f\" ]; then emit \"$f\"; fi;"
        " done;"
        " fi");
}

} // namespace

SshLink::SshLink(QString user, QString host, int port, bool tailscaleSsh)
    : m_target(user + "@" + host), m_port(port), m_tailscaleSsh(tailscaleSsh) {}

void SshLink::trustNextKey() { m_trustNext = true; }

CommandResult SshLink::exec(const QStringList &argv, const QString &input, int timeoutMs) {
    QMutexLocker lock(&m_execLock);
    QStringList args;
    if (m_tailscaleSsh) {
        // tailscale ssh reaches a peer that has Tailscale SSH on, without a
        // separate sshd key. The destination is the tailnet name.
        args << "tailscale" << "ssh" << m_target;
    } else {
        args << "ssh" << "-T" << "-p" << QString::number(m_port) << "-o" << "BatchMode=yes" << "-o"
             << "ConnectTimeout=8" << "-o"
             << (m_trustNext ? "StrictHostKeyChecking=accept-new" : "StrictHostKeyChecking=yes") << m_target;
        m_trustNext = false;
    }
    args += argv;
    return runProcess(args.first(), args.mid(1), input, timeoutMs);
}

CommandResult RemoteCommands::run(const QString &program, const QStringList &args, const QString &input, int timeoutMs) {
    auto result = m_link->exec(QStringList{program} + args, input, timeoutMs);
    const auto message = result.err + result.out;
    if (result.code == 127 || message.contains("command not found") || message.contains("not found"))
        result.missing = true;
    return result;
}

OsProfile profileForRelease(const QString &id, const QString &idLike) {
    OsProfile profile;
    const auto blob = (id + " " + idLike).toLower();
    if (blob.contains("debian") || blob.contains("ubuntu")) {
        profile.family = "debian";
        profile.sambaUnit = "smbd";
        profile.nfsPackage = "nfs-kernel-server";
        profile.iscsiUnit = "rtslib-fb-targetctl";
    }
    return profile;
}

bool remoteTargetOk(const QString &user, const QString &host, int port) {
    static const QRegularExpression hostRe("^[A-Za-z0-9][A-Za-z0-9.-]{0,253}$");
    if (!accountNameOk(user) || port < 1 || port > 65535)
        return false;
    if (!hostRe.match(host).hasMatch() || host.contains("..") || host.endsWith('.'))
        return false;
    return true;
}

QVector<RemoteHost> tailscalePeers(const QString &json) {
    QVector<RemoteHost> hosts;
    const auto root = QJsonDocument::fromJson(json.toUtf8()).object();
    const auto self = root.value("Self").toObject().value("DNSName").toString();
    const auto peers = root.value("Peer").toObject();
    for (const auto &key : peers.keys()) {
        const auto peer = peers.value(key).toObject();
        if (!peer.value("Online").toBool())
            continue;
        auto dns = peer.value("DNSName").toString();
        while (dns.endsWith('.'))
            dns.chop(1);
        QString ip;
        for (const auto &value : peer.value("TailscaleIPs").toArray()) {
            const auto candidate = value.toString();
            if (candidate.isEmpty() || candidate.contains(':'))
                continue;
            ip = candidate;
            break;
        }
        if (dns.isEmpty() && ip.isEmpty())
            continue;
        if (!self.isEmpty() && dns == self.left(self.size() - (self.endsWith('.') ? 1 : 0)))
            continue;
        RemoteHost host;
        host.name = peer.value("HostName").toString();
        if (host.name.isEmpty())
            host.name = dns.isEmpty() ? ip : dns.section('.', 0, 0);
        host.host = dns.isEmpty() ? ip : dns;
        host.address = ip;
        host.via = "tailscale";
        host.tailscaleSsh = !peer.value("sshHostKeys").toArray().isEmpty();
        if (remoteTargetOk("peer", host.host, 22))
            hosts.append(host);
    }
    return hosts;
}

QStringList missingPackages(const OsProfile &profile, bool samba, bool nfs, bool iscsi, bool python) {
    QStringList packages;
    if (!python)
        packages << "python3";
    if (!samba)
        packages << profile.sambaPackage;
    if (!nfs)
        packages << profile.nfsPackage;
    if (!iscsi)
        packages << profile.iscsiPackage;
    return packages;
}

QString installCommand(const OsProfile &profile, const QStringList &packages) {
    if (packages.isEmpty())
        return {};
    QStringList lines;
    for (const auto &argv : installArgv(profile, packages))
        lines << argv.join(' ');
    return lines.join('\n');
}

QVector<QStringList> installArgv(const OsProfile &profile, const QStringList &packages) {
    static const QStringList allowed{"python3", "samba", "nfs-utils", "nfs-kernel-server", "targetcli-fb"};
    QStringList clean;
    for (const auto &package : packages) {
        if (allowed.contains(package) && !clean.contains(package))
            clean << package;
    }
    if (clean.isEmpty())
        return {};
    if (profile.family == "debian") {
        QStringList install{"sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y"};
        install += clean;
        return {{"sudo", "-n", "apt-get", "update"}, install};
    }
    QStringList install{"sudo", "-n", "pacman", "-S", "--needed", "--noconfirm"};
    install += clean;
    return {install};
}

RemoteNeed probeRemote(RemoteLink *link) {
    RemoteNeed need;
    const auto release = link->exec({"cat", "/etc/os-release"}, {}, 20000);
    const auto releaseMessage = release.err + release.out;
    if (release.missing) {
        need.error = release.err;
        return need;
    }
    if (releaseMessage.contains("Host key verification failed") || releaseMessage.contains("not known")) {
        need.hostKeyDenied = true;
        need.error = "This computer has not trusted that host key yet.";
        return need;
    }
    if (release.code != 0) {
        need.error = releaseMessage.trimmed().isEmpty() ? QStringLiteral("Could not reach that computer.")
                                                         : releaseMessage.trimmed();
        return need;
    }
    need.connected = true;
    need.profile = profileForRelease(releaseValue(release.out, "ID"), releaseValue(release.out, "ID_LIKE"));
    need.sudo = link->exec({"sudo", "-n", "true"}, {}, 15000).code == 0;
    const bool samba = toolExists(link, {"/usr/sbin/smbd", "/usr/bin/smbd"});
    const bool nfs = toolExists(link, {"/usr/sbin/exportfs", "/usr/bin/exportfs"});
    const bool iscsi = toolExists(link, {"/usr/bin/targetcli", "/usr/sbin/targetcli"});
    const bool python = toolExists(link, {"/usr/bin/python3"});
    need.packages = missingPackages(need.profile, samba, nfs, iscsi, python);
    need.command = installCommand(need.profile, need.packages);
    if (!need.sudo)
        need.error = "The SSH user needs passwordless sudo before Shares can install packages or save.";
    return need;
}

QStringList remoteBundleArgv() {
    const auto script = remoteBundleScript();
    QString quoted = QStringLiteral("'");
    for (const auto &ch : script) {
        if (ch == u'\'')
            quoted += QStringLiteral("'\\''");
        else
            quoted += ch;
    }
    quoted += u'\'';
    // OpenSSH joins the remote command for a shell. The quotes are part of
    // this one argument so the script is not split on spaces.
    return {"sudo", "-n", "sh", "-c", quoted};
}

QByteArray remoteBundlePayload(const QVector<QPair<QString, QByteArray>> &files) {
    QByteArray out;
    for (const auto &file : files) {
        out += "FILE " + file.first.toUtf8() + " " + QByteArray::number(file.second.size()) + "\n";
        out += file.second;
        out += "\n";
    }
    return out;
}

bool writeRemoteBundle(const QByteArray &payload, const QString &root, QString *error) {
    int pos = 0;
    while (pos < payload.size()) {
        int end = payload.indexOf('\n', pos);
        if (end < 0)
            end = payload.size();
        const auto line = payload.mid(pos, end - pos);
        pos = end < payload.size() ? end + 1 : payload.size();
        if (line.isEmpty() || line.startsWith("MISS ") || line.startsWith("SKIP ") || line.startsWith("ERR "))
            continue;
        if (!line.startsWith("FILE ")) {
            if (error && error->isEmpty())
                *error = "The share file listing was not in the expected form.";
            return false;
        }
        const auto rest = line.mid(5);
        const int space = rest.lastIndexOf(' ');
        if (space <= 0) {
            if (error && error->isEmpty())
                *error = "The share file listing was not in the expected form.";
            return false;
        }
        const auto path = QString::fromUtf8(rest.left(space));
        bool sizeOk = false;
        const int size = rest.mid(space + 1).toInt(&sizeOk);
        if (!sizeOk || size < 0 || size > 1048576 || pos + size > payload.size()) {
            if (error && error->isEmpty())
                *error = "The share file listing was cut off.";
            return false;
        }
        const auto body = payload.mid(pos, size);
        pos += size;
        if (pos < payload.size() && payload.at(pos) == '\n')
            ++pos;
        if (!bundlePathOk(path))
            continue;
        if (!writeBundleFile(root, path, body, error))
            return false;
    }
    return true;
}

bool pullRemoteFiles(RemoteLink *link, const QString &root, QString *error) {
    const auto result = link->exec(remoteBundleArgv(), {}, 20000);
    const auto message = result.err + result.out;
    if (result.code != 0) {
        if (message.contains("a password is required") || message.contains("sudo")) {
            if (error && error->isEmpty())
                *error = "The SSH user needs passwordless sudo to read the share files.";
        } else if (error && error->isEmpty()) {
            *error = message.trimmed().isEmpty() ? QStringLiteral("Could not read the share files.") : message.trimmed();
        }
        return false;
    }
    return writeRemoteBundle(result.out.toUtf8(), root, error);
}

bool installRemotePackages(RemoteLink *link, const OsProfile &profile, const QStringList &packages, QString *error) {
    const auto commands = installArgv(profile, packages);
    if (commands.isEmpty()) {
        if (error)
            *error = "There is no package list for that computer.";
        return false;
    }
    for (const auto &argv : commands) {
        const auto result = link->exec(argv, {}, 180000);
        if (result.code != 0) {
            const auto message = (result.err + "\n" + result.out).trimmed();
            if (error)
                *error = message.isEmpty() ? QStringLiteral("The package install failed.") : message;
            return false;
        }
    }
    return true;
}

bool applyRemotePlan(RemoteLink *link, const QByteArray &helper, const QByteArray &plan, QString *error, QString *output) {
    const auto directory = link->exec({"sudo", "-n", "mkdir", "-p", "/usr/local/lib/shares"}, {}, 20000);
    if (directory.code != 0) {
        if (error)
            *error = "Could not prepare /usr/local/lib/shares on that computer.";
        return false;
    }
    // The helper is a fixed program. The plan follows on a later stdin, so a
    // share path or a password is never part of the SSH command text.
    const auto sent = link->exec({"sudo", "-n", "tee", "/usr/local/lib/shares/apply.py"}, QString::fromUtf8(helper), 20000);
    if (sent.code != 0) {
        if (error)
            *error = "Could not install the apply helper on that computer.";
        return false;
    }
    const auto applied = link->exec({"sudo", "-n", "python3", "/usr/local/lib/shares/apply.py", "--root", "/"},
                                    QString::fromUtf8(plan), 120000);
    if (output)
        output->append(applied.out);
    if (applied.code != 0) {
        const auto message = applied.err.trimmed().isEmpty() ? applied.out.trimmed() : applied.err.trimmed();
        if (error)
            *error = message.isEmpty() ? QStringLiteral("The change was not applied.") : message;
        return false;
    }
    return true;
}
