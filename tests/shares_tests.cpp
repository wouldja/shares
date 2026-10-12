#include <algorithm>
#include <QClipboard>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QGuiApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QSignalSpy>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QtTest>

#include "filepicker.h"

#include "backend.h"
#include "config.h"
#include "remote.h"
#include "store.h"
#include "theme.h"

namespace {

class FakeCommands : public Commands {
public:
    QHash<QString, CommandResult> exact;
    QVector<QStringList> calls;
    QStringList inputs;

    CommandResult run(const QString &program, const QStringList &args, const QString &input = {}, int = 8000) override {
        calls.append(QStringList{program} + args);
        inputs.append(input);
        const auto key = (QStringList{program} + args).join(' ');
        if (exact.contains(key))
            return exact.value(key);
        return {0, {}, {}, false};
    }

    bool parallelProbes() const override { return false; }
};

bool writeFile(const QString &path, const QString &body) {
    QDir().mkpath(QFileInfo(path).absolutePath());
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly))
        return false;
    return file.write(body.toUtf8()) == body.toUtf8().size();
}

QString joinedCalls(const QVector<QStringList> &calls) {
    QStringList lines;
    for (const auto &call : calls)
        lines << call.join(' ');
    return lines.join('\n');
}

QString readFile(const QString &path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return {};
    return QString::fromUtf8(file.readAll());
}

} // namespace

class ScriptedLink : public RemoteLink {
public:
    QHash<QString, CommandResult> exact;
    QVector<QPair<QString, CommandResult>> queued;
    QVector<QStringList> calls;
    QStringList inputs;
    bool installed = false;

    CommandResult lookup(const QStringList &argv) {
        const auto key = argv.join(' ');
        for (int i = 0; i < queued.size(); ++i) {
            if (queued.at(i).first == key) {
                const auto result = queued.at(i).second;
                queued.removeAt(i);
                return result;
            }
        }
        if (key.contains("apt-get install") || key.contains("pacman -S"))
            installed = true;
        if (exact.contains(key))
            return exact.value(key);
        if (argv.value(0) == "test" && argv.value(1) == "-x")
            return {installed || key == "test -x /usr/bin/python3" ? 0 : 1, {}, {}, false};
        if (key.startsWith("sudo -n cat"))
            return {1, {}, "cat: No such file or directory", false};
        if (key.startsWith("sudo -n "))
            return {0, {}, {}, false};
        if (argv.value(0) == "hostname")
            return {0, "pve\n", {}, false};
        return {1, {}, {}, false};
    }

    // The connect probe is one shell. Older stubs still describe cat, sudo, and
    // test -x, and this builds the same report the remote script would print.
    CommandResult synthesizeProbe() {
        const auto os = lookup({"cat", "/etc/os-release"});
        if (os.code != 0)
            return os;
        QString out = os.out;
        if (!out.endsWith('\n'))
            out += '\n';
        out += "SHARES-PROBE\n";
        const auto sudo = lookup({"sudo", "-n", "true"});
        out += sudo.code == 0 ? "SUDO 0\n" : "SUDO 1\n";
        for (const auto &path : remoteProbeToolPaths()) {
            const auto tool = lookup({"test", "-x", path});
            out += QString("TOOL %1 %2\n").arg(path, tool.code == 0 ? "0" : "1");
        }
        return {0, out, {}, false};
    }

    CommandResult exec(const QStringList &argv, const QString &input, int) override {
        calls.append(argv);
        inputs.append(input);
        if (argv == remoteProbeArgv()) {
            const auto key = argv.join(' ');
            for (int i = 0; i < queued.size(); ++i) {
                if (queued.at(i).first == key) {
                    const auto result = queued.at(i).second;
                    queued.removeAt(i);
                    return result;
                }
            }
            if (exact.contains(key))
                return exact.value(key);
            return synthesizeProbe();
        }
        return lookup(argv);
    }
};

struct PyRun {
    int code = -1;
    QString out;
    QString err;
};

PyRun runApply(const QStringList &args, const QByteArray &input) {
    PyRun run;
    QProcess process;
    process.start(QStringLiteral("python3"), QStringList{QString(SHARES_APPLY_PY)} + args);
    if (!process.waitForStarted(5000)) {
        run.err = process.errorString();
        return run;
    }
    process.write(input);
    process.closeWriteChannel();
    process.waitForFinished(20000);
    run.code = process.exitCode();
    run.out = QString::fromUtf8(process.readAllStandardOutput());
    run.err = QString::fromUtf8(process.readAllStandardError());
    return run;
}

QByteArray applyPlanJson(const QString &path, const QString &body, const QJsonArray &command) {
    QJsonArray commands;
    if (!command.isEmpty())
        commands.append(QJsonObject{{"args", command}, {"input", ""}});
    const QJsonObject plan{{"files", QJsonArray{QJsonObject{{"path", path}, {"body", body}}}}, {"commands", commands}};
    return QJsonDocument(plan).toJson(QJsonDocument::Compact);
}

class FakePicker : public FilePicker {
public:
    int folders = 0;
    int files = 0;
    QString title;
    QString folder;
    QString suggested;

    void chooseFolder(const QString &title, const QString &currentFolder) override {
        ++folders;
        this->title = title;
        folder = currentFolder;
    }

    void chooseNewFile(const QString &title, const QString &currentFolder, const QString &suggestedName) override {
        ++files;
        this->title = title;
        folder = currentFolder;
        suggested = suggestedName;
    }

    void send(const QString &path) { emit chosen(path); }
    void cancel() { emit cancelled(); }
};

class SharesTests : public QObject {
    Q_OBJECT

private slots:
    void presetsRoundTrip() {
        SambaShare share;
        share.name = "photos";
        share.path = "/srv/photos";
        share.windowsAcls = true;
        share.shadowCopy = true;
        share.macos = true;
        share.audit = true;
        share.guest = true;
        SambaGlobal global;
        global.macos = true;
        const auto text = sambaShareText(global, {share});
        QVERIFY(text.contains("acl_xattr"));
        QVERIFY(text.contains("fruit"));
        QVERIFY(text.contains("full_audit"));
        const auto parsed = parseSamba(text);
        QCOMPARE(parsed.shares.size(), 1);
        QVERIFY(parsed.shares.first().windowsAcls);
        QVERIFY(parsed.shares.first().shadowCopy);
        QVERIFY(parsed.shares.first().macos);
        QVERIFY(parsed.shares.first().audit);
        QVERIFY(parsed.shares.first().guest);
        QVERIFY(parsed.global.macos);
    }

    void nfsDisabledRoundTrip() {
        NfsExport exp;
        exp.path = "/srv/backup";
        exp.enabled = false;
        exp.clients.append(NfsClient{"10.0.0.0/24", "ro,sync,no_subtree_check"});
        const auto parsed = parseNfs(nfsText({exp}));
        QCOMPARE(parsed.size(), 1);
        QVERIFY(!parsed.first().enabled);
        QCOMPARE(parsed.first().clients.first().host, QString("10.0.0.0/24"));
    }

    void commandWhitelistRejectsAShell() {
        QVERIFY(commandAllowed({"exportfs", "-ra"}));
        QVERIFY(commandAllowed({"curl", "-sf", "http://127.0.0.1:9000/rustfs/admin/v3/buckets"}));
        QVERIFY(commandAllowed({"curl", "-sf", "--connect-timeout", "2", "--max-time", "3",
                                "http://127.0.0.1:9000/rustfs/admin/v3/buckets"}));
        QVERIFY(!commandAllowed({"curl", "-sf", "--connect-timeout", "20", "--max-time", "3",
                                 "http://127.0.0.1:9000/rustfs/admin/v3/buckets"}));
        QVERIFY(!commandAllowed({"bash", "-c", "id"}));
        QVERIFY(!commandAllowed({"curl", "-sf", "http://example.com/rustfs/admin/v3/buckets"}));
        QVERIFY(!commandAllowed({"mkdir", "-p", "/srv/../etc"}));
        QVERIFY(!commandAllowed({"smbpasswd", "-s", "-a", "Ada"}));
    }

    void planJsonRoundTripKeepsThePasswordOffTheArguments() {
        Plan plan;
        plan.files.append(qMakePair(QString("etc/exports.d/shares.exports"), QString("/srv/photos *(rw)\n")));
        plan.commands.append(PlannedCommand{{"smbpasswd", "-s", "-a", "ada"}, "secret\nsecret\n"});
        bool ok = false;
        const auto back = planFromJson(planToJson(plan), &ok);
        QVERIFY(ok);
        QCOMPARE(back.files.first().second, plan.files.first().second);
        QCOMPARE(back.commands.first().args, plan.commands.first().args);
        QCOMPARE(back.commands.first().input, QString("secret\nsecret\n"));
    }

    void emptyLibraryHasNoRows() {
        QTemporaryDir dir;
        FakeCommands commands;
        commands.exact.insert("hostname -s", {0, "files\n", {}, false});
        commands.exact.insert("hostname -f", {0, "files\n", {}, false});
        Backend backend(dir.path(), &commands);
        QCOMPARE(backend.protocol(), 0);
        QCOMPARE(backend.rows().size(), 0);
        QCOMPARE(backend.reachable(), QStringList{"files.local"});
        QVERIFY(!backend.dirty());
    }

    void setProtocolClamps() {
        QTemporaryDir dir;
        FakeCommands commands;
        Backend backend(dir.path(), &commands);
        backend.setProtocol(9);
        QCOMPARE(backend.protocol(), 3);
        QCOMPARE(backend.protocolName(), QString("S3"));
        backend.setProtocol(-3);
        QCOMPARE(backend.protocol(), 0);
    }

    void createRejectsABlankName() {
        QTemporaryDir dir;
        FakeCommands commands;
        Backend backend(dir.path(), &commands);
        QVERIFY(!backend.create("  ", "/srv/clips"));
        QCOMPARE(backend.rows().size(), 0);
        QCOMPARE(backend.error(), QString("A share needs a name and a path."));
    }

    void createUndoAndCopyUseTheDiscoveredName() {
        QTemporaryDir dir;
        FakeCommands commands;
        commands.exact.insert("hostname -s", {0, "files\n", {}, false});
        commands.exact.insert("hostname -f", {0, "files\n", {}, false});
        Backend backend(dir.path(), &commands);
        QVERIFY(backend.create("photos", "/srv/photos"));
        QVERIFY(backend.create("work", "/srv/work"));
        backend.setFilter("work");
        QCOMPARE(backend.rows().size(), 1);
        QCOMPARE(backend.detail().value("name").toString(), QString("work"));
        backend.setFilter("");
        backend.select(backend.rows().first().toMap().value("id").toInt());
        backend.copyAddress();
        backend.move(-1);
        QCOMPARE(backend.detail().value("name").toString(), QString("work"));
        QCOMPARE(QGuiApplication::clipboard()->text(), QString("smb://files.local/photos"));
        QVERIFY(!QGuiApplication::clipboard()->text().contains("192.168"));
        backend.undo();
        backend.undo();
        QCOMPARE(backend.rows().size(), 0);
        QVERIFY(!backend.dirty());
        backend.redo();
        QCOMPARE(backend.rows().size(), 1);
    }

    void guestBadgeFollowsTheSwitch() {
        QTemporaryDir dir;
        FakeCommands commands;
        Backend backend(dir.path(), &commands);
        QVERIFY(backend.create("photos", "/srv/photos"));
        backend.toggle("guest");
        const auto badges = backend.rows().first().toMap().value("badges").toList();
        QCOMPARE(badges.first().toMap().value("text").toString(), QString("Guest"));
        QVERIFY(badges.first().toMap().value("warn").toBool());
    }

    void saveWritesSharesAndDoesNotRemoveTheFolder() {
        QTemporaryDir dir;
        FakeCommands commands;
        Backend backend(dir.path(), &commands);
        QVERIFY(backend.create("photos", "/srv/photos"));
        QVERIFY(backend.applyEditor("comment=Family\nvalid users=ada\ndirectory mode=0755\ncreate path=yes\nadvanced:\nfollow symlinks = yes\n"));
        QVERIFY(backend.save());
        const auto shares = readFile(dir.path() + "/etc/samba/shares.conf");
        QVERIFY(shares.contains("[photos]"));
        QVERIFY(shares.contains("path = /srv/photos"));
        QVERIFY(shares.contains("valid users = ada"));
        QVERIFY(shares.contains("follow symlinks = yes"));
        const auto smb = readFile(dir.path() + "/etc/samba/smb.conf");
        QVERIFY(smb.contains("include = /etc/samba/shares.conf"));
        QVERIFY(!smb.contains("[photos]"));
        QVERIFY(!QFile::exists(dir.path() + "/etc/samba/smb.conf.bak"));
        const auto joined = joinedCalls(commands.calls);
        QVERIFY(joined.contains("mkdir"));
        QVERIFY(joined.contains("chmod"));
        QVERIFY(!joined.contains(" rm "));
        QVERIFY(!joined.contains("targetcli saveconfig"));
        QVERIFY(!joined.contains("systemctl start target"));
        QVERIFY(backend.create("clips", "/tmp/$(id)"));
        QVERIFY(backend.applyEditor("create path=yes\nadvanced:\n"));
        QVERIFY(!backend.save());
        QVERIFY(backend.error().contains("cannot be created"));
    }

    void saveMigratesSmbConfAndKeepsABackup() {
        QTemporaryDir dir;
        QVERIFY(writeFile(dir.path() + "/etc/samba/smb.conf", "[global]\n   workgroup = FILES\n\n[photos]\n   path = /srv/photos\n"));
        FakeCommands commands;
        Backend backend(dir.path(), &commands);
        QCOMPARE(backend.rows().size(), 1);
        QVERIFY(backend.dirty());
        QVERIFY(backend.save());
        QVERIFY(readFile(dir.path() + "/etc/samba/shares.conf").contains("[photos]"));
        QVERIFY(!readFile(dir.path() + "/etc/samba/smb.conf").contains("[photos]"));
        QVERIFY(readFile(dir.path() + "/etc/samba/smb.conf.bak").contains("[photos]"));
        QVERIFY(readFile(dir.path() + "/etc/samba/smb.conf").contains("workgroup = FILES"));
    }

    void saveKeepsHomesAndIgnoresExportComments() {
        QTemporaryDir dir;
        QVERIFY(writeFile(dir.path() + "/etc/samba/smb.conf",
                          "[global]\n   workgroup = FILES\n\n[homes]\n   comment = Home Directories\n"
                          "   browseable = no\n\n[photos]\n   path = /srv/photos\n"));
        QVERIFY(writeFile(dir.path() + "/etc/exports",
                          "# /etc/exports: the access control list for filesystems which may be exported\n"
                          "#\tto NFS clients.  See exports(5).\n"
                          "# /srv/homes       hostname1(rw,sync,no_subtree_check)\n"
                          "/srv/photos *(rw,sync,no_subtree_check)\n"));
        FakeCommands commands;
        Backend backend(dir.path(), &commands);
        QCOMPARE(backend.rows().size(), 1);
        QCOMPARE(backend.rows().first().toMap().value("name").toString(), QString("photos"));
        QVERIFY(backend.dirty());
        backend.setProtocol(1);
        QCOMPARE(backend.rows().size(), 2);
        QStringList paths;
        for (const auto &row : backend.rows())
            paths << row.toMap().value("path").toString();
        QVERIFY(paths.contains("/srv/photos"));
        QVERIFY(paths.contains("/srv/homes"));
        QVERIFY(!paths.contains("to"));
        backend.setProtocol(0);
        QVERIFY(backend.save());
        QVERIFY(!backend.error().contains("absolute"));
        const auto smb = readFile(dir.path() + "/etc/samba/smb.conf");
        QVERIFY(smb.contains("[homes]"));
        QVERIFY(!smb.contains("[photos]"));
        QVERIFY(readFile(dir.path() + "/etc/samba/shares.conf").contains("path = /srv/photos"));
        Backend again(dir.path(), &commands);
        QCOMPARE(again.rows().size(), 1);
        QCOMPARE(again.rows().first().toMap().value("name").toString(), QString("photos"));
        QVERIFY(!again.dirty());
    }

    void iscsiSaveKeepsTheImage() {
        QTemporaryDir dir;
        FakeCommands commands;
        commands.exact.insert("hostname -s", {0, "files\n", {}, false});
        commands.exact.insert("hostname -f", {0, "files\n", {}, false});
        Backend backend(dir.path(), &commands);
        backend.setProtocol(2);
        QVERIFY(backend.create("clips", "/srv/iscsi/clips.img"));
        QVERIFY(backend.detail().value("path").toString().startsWith("iqn."));
        QVERIFY(backend.detail().value("path").toString().contains("local.files:clips"));
        const auto backing = backend.detail().value("facts").toList().first().toMap().value("value").toString();
        QVERIFY(backing.contains("/srv/iscsi/clips.img"));
        QVERIFY(backend.save());
        QVERIFY(joinedCalls(commands.calls).contains("targetcli saveconfig"));
        const auto record = readFile(dir.path() + "/etc/shares/iscsi.json");
        QVERIFY(record.contains("/srv/iscsi/clips.img"));
        const auto perms = QFileInfo(dir.path() + "/etc/shares/iscsi.json").permissions();
        QVERIFY(perms & QFileDevice::ReadOwner);
        QVERIFY(!(perms & QFileDevice::ReadGroup));
        QVERIFY(!(perms & QFileDevice::ReadOther));
        const auto before = commands.calls.size();
        backend.removeSelected();
        QVERIFY(backend.save());
        QVector<QStringList> removed;
        for (int i = before; i < commands.calls.size(); ++i)
            removed << commands.calls.at(i);
        const auto joined = joinedCalls(removed);
        QVERIFY(joined.contains("delete"));
        QVERIFY(joined.contains("targetcli saveconfig"));
        QVERIFY(!joined.contains("/srv/iscsi/clips.img"));
        QVERIFY(!joined.contains(" rm "));
    }

    void sambaPasswordStaysOnStdin() {
        QTemporaryDir dir;
        FakeCommands commands;
        Backend backend(dir.path(), &commands);
        QVERIFY(backend.setSambaPassword("ada", "secret"));
        QCOMPARE(commands.calls.last(), QStringList({"smbpasswd", "-s", "-a", "ada"}));
        QCOMPARE(commands.inputs.last(), QString("secret\nsecret\n"));
        QVERIFY(backend.userLine().contains("ada · Samba"));
    }

    void cephBucketCreateIsRefused() {
        QTemporaryDir dir;
        FakeCommands commands;
        commands.exact.insert("radosgw-admin --version", {0, "ceph version\n", {}, false});
        Backend backend(dir.path(), &commands);
        backend.setProtocol(3);
        QVERIFY(!backend.create("photos", "ceph"));
        QVERIFY(backend.error().contains("S3 API"));
    }

    void minioBucketCreateUsesMc() {
        QTemporaryDir dir;
        FakeCommands commands;
        commands.exact.insert("mc --version", {0, "mc version\n", {}, false});
        commands.exact.insert("mc ls local", {0, "photos/\n", {}, false});
        Backend backend(dir.path(), &commands);
        backend.setProtocol(3);
        QVERIFY(backend.create("photos", "minio"));
        QCOMPARE(backend.rows().size(), 1);
        QVERIFY(commands.calls.contains(QStringList{"mc", "mb", "local/photos"}));
    }

    void browseOpensAFolderAndFillsThePath() {
        QTemporaryDir dir;
        QVERIFY(QDir().mkpath(dir.path() + "/photos"));
        FakeCommands commands;
        FakePicker picker;
        Backend backend(dir.path(), &commands, &picker);
        QSignalSpy chosen(&backend, &Backend::createPathChosen);
        backend.browseForCreate(dir.path() + "/photos", "");
        QCOMPARE(picker.folders, 1);
        QCOMPARE(picker.files, 0);
        QCOMPARE(picker.title, QString("Folder to share"));
        QCOMPARE(picker.folder, dir.path() + "/photos");
        QVERIFY(backend.browsing());
        backend.browseForCreate(dir.path() + "/photos", "");
        QCOMPARE(picker.folders, 1);
        picker.cancel();
        QVERIFY(!backend.browsing());
        QCOMPARE(chosen.size(), 0);
        backend.browseForCreate(dir.path() + "/photos", "");
        picker.send("photos");
        QVERIFY(!backend.browsing());
        QCOMPARE(chosen.size(), 0);
        QVERIFY(backend.error().contains("absolute"));
        backend.browseForCreate(dir.path() + "/photos", "");
        picker.send("/srv/photos");
        QCOMPARE(chosen.size(), 1);
        QCOMPARE(chosen.first().first().toString(), QString("/srv/photos"));
        QVERIFY(backend.create("photos", "/srv/photos"));
        QCOMPARE(backend.rows().first().toMap().value("path").toString(), QString("/srv/photos"));
    }

    void browseOpensAnImageForIscsiAndSkipsS3() {
        QTemporaryDir dir;
        FakeCommands commands;
        FakePicker picker;
        Backend backend(dir.path(), &commands, &picker);
        backend.setProtocol(2);
        backend.browseForCreate("", "clips");
        QCOMPARE(picker.files, 1);
        QCOMPARE(picker.title, QString("Disk image"));
        QCOMPARE(picker.suggested, QString("clips.img"));
        QVERIFY(QDir(picker.folder).exists());
        picker.cancel();
        backend.setProtocol(3);
        backend.browseForCreate("", "");
        QCOMPARE(picker.files, 1);
        QCOMPARE(picker.folders, 0);
        QVERIFY(backend.error().contains("no folder"));
    }

    void remoteBrowseReadsTheServerNotThisComputer() {
        QTemporaryDir dir;
        QVERIFY(QDir().mkpath(dir.path() + "/only-local"));
        FakeCommands commands;
        commands.exact.insert("tailscale status --json", {0, "{}", {}, false});
        ScriptedLink link;
        link.exact.insert("cat /etc/os-release", {0, "ID=debian\nID_LIKE=debian\n", {}, false});
        link.exact.insert("sudo -n true", {0, {}, {}, false});
        link.exact.insert("test -d '/'", {0, {}, {}, false});
        link.exact.insert("ls -1 -A -p --color=never --quoting-style=literal -- '/'", {0, "srv/\nphotos\n", {}, false});
        link.exact.insert("test -d '/srv'", {0, {}, {}, false});
        link.exact.insert("ls -1 -A -p --color=never --quoting-style=literal -- '/srv'",
                          {0, "photos/\ndisk.img\n", {}, false});
        link.exact.insert("mkdir -- '/srv/new folder'", {0, {}, {}, false});
        FakePicker picker;
        Backend backend(dir.path(), &commands, &picker, &link);
        backend.setHostsFile(dir.path() + "/hosts.json");
        QVERIFY(backend.addHost("root", "files.example.net", 22));
        QVERIFY(backend.remote());
        QSignalSpy chosen(&backend, &Backend::createPathChosen);
        backend.browseForCreate(dir.path() + "/only-local", "");
        QVERIFY(backend.browsing());
        QCOMPARE(picker.folders, 0);
        QCOMPARE(picker.files, 0);
        QCOMPARE(backend.browsePath(), QString("/"));
        QCOMPARE(backend.browseRows().size(), 2);
        QVERIFY(backend.browseRows().first().toMap().value("dir").toBool());
        QCOMPARE(backend.browseRows().first().toMap().value("name").toString(), QString("srv"));
        backend.browseEnter(1);
        QVERIFY(backend.error().contains("file"));
        QCOMPARE(backend.browsePath(), QString("/"));
        backend.browseEnter(0);
        QCOMPARE(backend.browsePath(), QString("/srv"));
        QVERIFY(!backend.browseMake("o'brien"));
        QVERIFY(joinedCalls(link.calls).contains("mkdir -- '/srv/o'\\''brien'"));
        QVERIFY(backend.browseMake("new folder"));
        QVERIFY(joinedCalls(link.calls).contains("mkdir -- '/srv/new folder'"));
        backend.browseChoose("");
        QCOMPARE(chosen.size(), 1);
        QCOMPARE(chosen.first().first().toString(), QString("/srv"));
        QVERIFY(!backend.browsing());

        backend.setProtocol(2);
        backend.browseForCreate("/srv/clips.img", "clips");
        QVERIFY(backend.browsing());
        QCOMPARE(picker.files, 0);
        QCOMPARE(backend.browsePath(), QString("/srv"));
        QCOMPARE(backend.browseFile(), QString("clips.img"));
        backend.browseEnter(1);
        QCOMPARE(chosen.last().first().toString(), QString("/srv/disk.img"));
        QVERIFY(!backend.browsing());
    }

    void tailscalePeersSkipSelfAndOffline() {
        const auto peers = tailscalePeers(R"({
            "Self": {"DNSName": "files.example.ts.net."},
            "Peer": {
                "self": {"HostName": "files", "DNSName": "files.example.ts.net.", "Online": true,
                    "TailscaleIPs": ["100.100.100.1"], "sshHostKeys": []},
                "pve": {"HostName": "pve", "DNSName": "pve.example.ts.net.", "Online": true,
                    "TailscaleIPs": ["fd7a:115c:a1e0::2", "100.100.100.2"], "sshHostKeys": ["ssh-ed25519 AAAA"]},
                "off": {"HostName": "off", "DNSName": "off.example.ts.net.", "Online": false,
                    "TailscaleIPs": ["100.100.100.3"]},
                "store": {"HostName": "store", "DNSName": "", "Online": true,
                    "TailscaleIPs": ["100.100.100.4"]}
            }
        })");
        QCOMPARE(peers.size(), 2);
        QCOMPARE(peers.at(0).host, QString("pve.example.ts.net"));
        QCOMPARE(peers.at(0).address, QString("100.100.100.2"));
        QVERIFY(peers.at(0).tailscaleSsh);
        QCOMPARE(peers.at(0).via, QString("tailscale"));
        QCOMPARE(peers.at(1).host, QString("100.100.100.4"));
        QVERIFY(!peers.at(1).tailscaleSsh);
    }

    void remoteProfileAndPackages() {
        const auto debian = profileForRelease("debian", "debian");
        QCOMPARE(debian.family, QString("debian"));
        QCOMPARE(debian.sambaUnit, QString("smbd"));
        QCOMPARE(debian.nfsPackage, QString("nfs-kernel-server"));
        QCOMPARE(debian.iscsiUnit, QString("rtslib-fb-targetctl"));
        const auto ubuntu = profileForRelease("ubuntu", "debian");
        QCOMPARE(ubuntu.sambaUnit, QString("smbd"));
        const auto arch = profileForRelease("arch", "arch");
        QCOMPARE(arch.family, QString("arch"));
        QCOMPARE(arch.sambaUnit, QString("smb"));
        QCOMPARE(arch.nfsPackage, QString("nfs-utils"));
        QCOMPARE(arch.iscsiUnit, QString("target"));
        QCOMPARE(missingPackages(debian, false, false, false, false),
                 QStringList({"python3", "samba", "nfs-kernel-server", "targetcli-fb"}));
        const auto argv = installArgv(debian, {"curl", "samba", "samba"});
        QCOMPARE(argv.size(), 2);
        QCOMPARE(argv.first(), QStringList({"sudo", "-n", "apt-get", "update"}));
        QVERIFY(argv.last().contains("nfs-kernel-server") == false);
        QVERIFY(argv.last().contains("samba"));
        QVERIFY(!argv.last().contains("curl"));
        QCOMPARE(installArgv(arch, {"python3"}).first().first(), QString("sudo"));
        QVERIFY(installCommand(arch, {"python3"}).contains("pacman"));
    }

    void remoteTargetRejectsUnsafeNames() {
        QVERIFY(remoteTargetOk("ada", "files.example.net", 22));
        QVERIFY(remoteTargetOk("ada", "pve.example.ts.net", 22));
        QVERIFY(!remoteTargetOk("Ada", "files.example.net", 22));
        QVERIFY(!remoteTargetOk("ada", "files example.net", 22));
        QVERIFY(!remoteTargetOk("ada", "-files", 22));
        QVERIFY(!remoteTargetOk("ada", "a..b", 22));
        QVERIFY(!remoteTargetOk("ada", "files.", 22));
        QVERIFY(!remoteTargetOk("", "files", 22));
        QVERIFY(!remoteTargetOk("ada", "files", 0));
        QVERIFY(!remoteTargetOk("ada", "files", 70000));
        QVERIFY(commandAllowed({"systemctl", "start", "smbd"}));
        QVERIFY(commandAllowed({"systemctl", "reload", "rtslib-fb-targetctl"}));
        QVERIFY(!commandAllowed({"bash", "-c", "id"}));
    }

    void debianPlanStartsSmbd() {
        QTemporaryDir dir;
        FakeCommands commands;
        Library library(dir.path(), &commands);
        library.setProfile(profileForRelease("debian", "debian"));
        SambaConfig config;
        SambaShare share;
        share.name = "photos";
        share.path = "/srv/photos";
        config.shares.append(share);
        const auto plan = library.plan(config, {}, {});
        QVERIFY(plan.error.isEmpty());
        bool smbd = false;
        bool smb = false;
        for (const auto &command : plan.commands) {
            if (command.args == QStringList{"systemctl", "start", "smbd"})
                smbd = true;
            if (command.args == QStringList{"systemctl", "start", "smb"})
                smb = true;
        }
        QVERIFY(smbd);
        QVERIFY(!smb);
    }

    void applyHelperWritesAndRefuses() {
        if (QStandardPaths::findExecutable(QStringLiteral("python3")).isEmpty())
            QSKIP("python3 is not installed");
        QTemporaryDir dir;
        const auto made = dir.path() + "/made";
        const auto wrote = runApply({QStringLiteral("--root"), dir.path()},
                                     applyPlanJson("etc/samba/shares.conf", "[photos]\n   path = /srv/photos\n",
                                                   QJsonArray{"mkdir", "-p", made}));
        QCOMPARE(wrote.code, 0);
        QVERIFY(readFile(dir.path() + "/etc/samba/shares.conf").contains("[photos]"));
        QVERIFY(QFileInfo(made).isDir());
        const auto escaped = runApply({QStringLiteral("--root"), dir.path()},
                                       applyPlanJson("etc/../passwd", "nope", {}));
        QVERIFY(escaped.code != 0);
        QVERIFY(escaped.err.contains("Refusing"));
        QVERIFY(!QFile::exists(dir.path() + "/passwd"));
        const auto shell = runApply({QStringLiteral("--root"), dir.path()},
                                     applyPlanJson("etc/samba/shares.conf", "[photos]\n", QJsonArray{"echo", "hi"}));
        QVERIFY(shell.code != 0);
        QVERIFY(shell.err.contains("Refusing"));
        const auto rooted = runApply({QStringLiteral("--root"), dir.path() + "/../outside"},
                                      applyPlanJson("etc/samba/shares.conf", "[photos]\n", {}));
        QVERIFY(rooted.code != 0);
        QVERIFY(rooted.err.contains("absolute"));
    }

    void tailscaleHostSaveStaysOnTheLink() {
        QTemporaryDir dir;
        FakeCommands commands;
        commands.exact.insert("tailscale status --json",
                              {0,
                               QString(R"({"Self":{"DNSName":"files.example.ts.net."},"Peer":{"pve":{"HostName":"pve","DNSName":"pve.example.ts.net.","Online":true,"TailscaleIPs":["100.100.100.2"],"sshHostKeys":["ssh-ed25519 AAAA"]},"off":{"HostName":"off","DNSName":"off.example.ts.net.","Online":false,"TailscaleIPs":["100.100.100.3"]}}})"),
                               {},
                               false});
        ScriptedLink link;
        link.exact.insert("cat /etc/os-release", {0, "ID=debian\nID_LIKE=debian\n", {}, false});
        link.exact.insert("sudo -n true", {0, {}, {}, false});
        Backend backend(dir.path(), &commands, nullptr, &link);
        backend.setHostsFile(dir.path() + "/hosts.json");
        const auto rows = backend.hosts();
        QStringList names;
        for (const auto &row : rows)
            names << row.toMap().value("name").toString();
        QVERIFY(names.contains("This computer"));
        QVERIFY(names.contains("pve"));
        QVERIFY(!names.contains("off"));
        const auto pve = std::find_if(rows.cbegin(), rows.cend(), [](const QVariant &row) {
            return row.toMap().value("name").toString() == "pve";
        });
        QVERIFY(pve != rows.cend());
        QVERIFY(pve->toMap().value("detail").toString().contains("Tailscale SSH"));
        QVERIFY(pve->toMap().value("detail").toString().contains("pve.example.ts.net"));
        int statusCalls = 0;
        for (const auto &call : commands.calls) {
            if (call.join(' ') == "tailscale status --json")
                ++statusCalls;
        }
        QCOMPARE(statusCalls, 1);

        QVERIFY(backend.addHost("share", "files.example.net", 22));
        QCOMPARE(backend.hostTitle(), QString("files"));
        QVERIFY(backend.canInstall());
        QVERIFY(backend.needsText().contains("nfs-kernel-server"));
        QVERIFY(backend.needsText().contains("apt-get install"));
        QVERIFY(!backend.needsText().contains("password"));
        const auto saved = readFile(dir.path() + "/hosts.json");
        QVERIFY(saved.contains("files.example.net"));
        QVERIFY(saved.contains("share"));
        QVERIFY(!saved.contains("password"));
        const auto perms = QFileInfo(dir.path() + "/hosts.json").permissions();
        QVERIFY(perms & QFileDevice::ReadOwner);
        QVERIFY(perms & QFileDevice::WriteOwner);
        QVERIFY(!(perms & QFileDevice::ReadGroup));
        QVERIFY(!(perms & QFileDevice::ReadOther));

        QVERIFY(backend.installNeeds());
        QVERIFY(!backend.canInstall());
        QVERIFY(backend.needsText().isEmpty());
        QVERIFY(joinedCalls(link.calls).contains("apt-get install"));
        QVERIFY(backend.create("photos", "/srv/photos"));
        QVERIFY(!backend.useHost("local"));
        QVERIFY(backend.error().contains("Save or discard"));
        QVERIFY(backend.save());
        int apply = -1;
        for (int i = 0; i < link.calls.size(); ++i) {
            if (link.calls.at(i).join(' ').contains("apply.py"))
                apply = i;
        }
        QVERIFY(apply >= 0);
        QVERIFY(link.inputs.at(apply).contains("[photos]"));
        QVERIFY(link.inputs.at(apply).contains("\"systemctl\",\"start\",\"smbd\""));
        QVERIFY(!QFile::exists(dir.path() + "/etc/samba/shares.conf"));
        QVERIFY(!joinedCalls(commands.calls).contains("targetcli saveconfig"));
        QVERIFY(!joinedCalls(commands.calls).contains("pkexec"));
        QVERIFY(backend.useHost("local"));
        QCOMPARE(backend.hostTitle(), QString("This computer"));
    }

    void remoteInstallWaitsForSudoAndATrustedKey() {
        QTemporaryDir dir;
        FakeCommands commands;
        ScriptedLink link;
        link.exact.insert("cat /etc/os-release", {0, "ID=debian\nID_LIKE=debian\n", {}, false});
        link.exact.insert("sudo -n true", {1, {}, "sudo: a password is required\n", false});
        Backend backend(dir.path(), &commands, nullptr, &link);
        QVERIFY(backend.addHost("share", "files.example.net", 22));
        QVERIFY(!backend.canInstall());
        QVERIFY(backend.needsText().contains("passwordless sudo"));
        QVERIFY(backend.needsText().contains("apt-get install"));
        QVERIFY(backend.error().contains("passwordless sudo"));
        QVERIFY(!backend.installNeeds());
        QVERIFY(!joinedCalls(link.calls).contains("apt-get"));

        ScriptedLink denied;
        denied.exact.insert("cat /etc/os-release", {1, {}, "Host key verification failed.\n", false});
        Backend other(dir.path(), &commands, nullptr, &denied);
        QVERIFY(!other.addHost("share", "pve.example.ts.net", 22));
        QVERIFY(other.canTrustHost());
        QVERIFY(other.error().contains("host key"));
        QVERIFY(!other.trustHost());
        QVERIFY(!joinedCalls(denied.calls).contains("StrictHostKeyChecking"));
    }

    void remoteInstallProceedsWhenSmbConfAlreadyHasShares() {
        QTemporaryDir dir;
        FakeCommands commands;
        commands.exact.insert("tailscale status --json", {0, "{}", {}, false});
        ScriptedLink link;
        link.exact.insert("cat /etc/os-release", {0, "ID=debian\nID_LIKE=debian\n", {}, false});
        link.exact.insert("sudo -n true", {0, {}, {}, false});
        const auto smb = QByteArray("[global]\n   workgroup = WORKGROUP\n[homes]\n   path = /home\n");
        link.exact.insert(remoteBundleArgv().join(' '),
                          {0, QString::fromUtf8(remoteBundlePayload({{QStringLiteral("/etc/samba/smb.conf"), smb}})), {}, false});
        Backend backend(dir.path(), &commands, nullptr, &link);
        backend.setHostsFile(dir.path() + "/hosts.json");
        QVERIFY(backend.addHost("root", "bandc.example.net", 22));
        QVERIFY(backend.dirty());
        QVERIFY(backend.notice().contains("smb.conf"));
        QVERIFY(backend.canInstall());
        QVERIFY(backend.installNeeds());
        QVERIFY(joinedCalls(link.calls).contains("apt-get install"));
        QVERIFY(backend.dirty());
        QVERIFY(backend.create("photos", "/srv/photos"));
        QVERIFY(!backend.installNeeds());
        QVERIFY(backend.error().contains("Save or discard"));
        QCOMPARE(joinedCalls(link.calls).count("apt-get install"), 1);
    }

    void disconnectReturnsHomeWhenTheServerOnlyLooksUnsaved() {
        QTemporaryDir dir;
        FakeCommands commands;
        commands.exact.insert("tailscale status --json", {0, "{}", {}, false});
        ScriptedLink link;
        link.exact.insert("cat /etc/os-release", {0, "ID=debian\nID_LIKE=debian\n", {}, false});
        link.exact.insert("sudo -n true", {0, {}, {}, false});
        const auto smb = QByteArray("[global]\n   workgroup = WORKGROUP\n[homes]\n   path = /home\n");
        link.exact.insert(remoteBundleArgv().join(' '),
                          {0, QString::fromUtf8(remoteBundlePayload({{QStringLiteral("/etc/samba/smb.conf"), smb}})), {}, false});
        Backend backend(dir.path(), &commands, nullptr, &link);
        backend.setHostsFile(dir.path() + "/hosts.json");
        QVERIFY(backend.addHost("root", "files.example.net", 22));
        QVERIFY(backend.remote());
        QVERIFY(backend.dirty());
        QVERIFY(!backend.canUndo());
        QVERIFY(backend.useHost("local"));
        QCOMPARE(backend.hostTitle(), QString("This computer"));
        QVERIFY(!backend.remote());

        QVERIFY(backend.addHost("root", "files.example.net", 22));
        QVERIFY(backend.create("photos", "/srv/photos"));
        QVERIFY(backend.canUndo());
        QVERIFY(!backend.useHost("local"));
        QVERIFY(backend.error().contains("Save or discard"));
        QCOMPARE(backend.hostTitle(), QString("files"));
        QVERIFY(backend.leaveComputer());
        QCOMPARE(backend.hostTitle(), QString("This computer"));
        QVERIFY(!backend.remote());
        QCOMPARE(backend.rows().size(), 0);
    }

    void tailscaleSshUsesRootWhenTheLoginIsRejected() {
        const auto previousUser = qgetenv("USER");
        qputenv("USER", "brian");
        QTemporaryDir dir;
        FakeCommands commands;
        commands.exact.insert("tailscale status --json",
                              {0,
                               QString(R"({"Self":{"DNSName":"omacrown.example.ts.net."},"Peer":{"bandc":{"HostName":"bandc","DNSName":"bandc.example.ts.net.","Online":true,"TailscaleIPs":["100.100.100.2"],"sshHostKeys":["ssh-ed25519 AAAA"]}}})"),
                               {},
                               false});
        ScriptedLink link;
        link.queued.append({QStringLiteral("cat /etc/os-release"),
                            {1, {}, "tailscale: tailnet policy does not permit you to SSH as user \"brian\"\n", false}});
        link.exact.insert("cat /etc/os-release", {0, "ID=debian\nID_LIKE=debian\n", {}, false});
        link.exact.insert("sudo -n true", {0, {}, {}, false});
        Backend backend(dir.path(), &commands, nullptr, &link);
        backend.setHostsFile(dir.path() + "/hosts.json");
        backend.refreshHosts();
        QString id;
        for (const auto &row : backend.hosts()) {
            const auto map = row.toMap();
            if (map.value("name").toString() == "bandc") {
                id = map.value("id").toString();
                QVERIFY(map.value("detail").toString().contains("brian"));
                QVERIFY(map.value("detail").toString().contains("Tailscale SSH"));
            }
        }
        QVERIFY(id.startsWith("ts:"));
        QVERIFY(!backend.useHost(id, "Brian"));
        QVERIFY(backend.error().contains("lowercase"));
        QCOMPARE(link.calls.size(), 0);

        QVERIFY(!backend.useHost(id, "share"));
        QCOMPARE(link.calls.size(), 1);
        QVERIFY(backend.error().contains("does not permit"));
        QVERIFY(!backend.error().contains("Root was refused"));

        link.queued.append({QStringLiteral("cat /etc/os-release"),
                            {1, {}, "tailscale: tailnet policy does not permit you to SSH as user \"brian\"\n", false}});
        QVERIFY(backend.useHost(id));
        QVERIFY(backend.remote());
        QCOMPARE(backend.hostTitle(), QString("bandc"));
        int releases = 0;
        const auto probe = remoteProbeArgv().join(' ');
        for (const auto &call : link.calls) {
            if (call.join(' ') == probe)
                ++releases;
        }
        QCOMPARE(releases, 3);
        qputenv("USER", previousUser);
    }

    void s3ListsWaitUntilThePageOpens() {
        QTemporaryDir dir;
        FakeCommands commands;
        commands.exact.insert("mc --version", {0, "mc version\n", {}, false});
        Backend backend(dir.path(), &commands);
        QVERIFY(!joinedCalls(commands.calls).contains("mc ls"));
        QVERIFY(!joinedCalls(commands.calls).contains("mc admin user list"));
        backend.setProtocol(3);
        QVERIFY(joinedCalls(commands.calls).contains("mc ls local"));
        QVERIFY(joinedCalls(commands.calls).contains("mc admin user list local"));
        backend.setProtocol(0);
        const auto lists = joinedCalls(commands.calls).count("mc ls local");
        backend.setProtocol(3);
        QCOMPARE(joinedCalls(commands.calls).count("mc ls local"), lists);
    }

    void sessionProbesFollowTheOpenPage() {
        QTemporaryDir dir;
        FakeCommands commands;
        Backend backend(dir.path(), &commands);
        QVERIFY(joinedCalls(commands.calls).contains("smbstatus -b"));
        QVERIFY(!joinedCalls(commands.calls).contains("targetcli sessions"));
        const auto ss = QStringLiteral("ss -H -t state established sport = :2049");
        QVERIFY(!joinedCalls(commands.calls).contains(ss));
        backend.setProtocol(1);
        QVERIFY(joinedCalls(commands.calls).contains(ss));
        backend.setProtocol(2);
        QVERIFY(joinedCalls(commands.calls).contains("targetcli sessions"));
        const auto before = joinedCalls(commands.calls).count("smbstatus -b");
        backend.setProtocol(0);
        QCOMPARE(joinedCalls(commands.calls).count("smbstatus -b"), before);
    }

    void remoteBundleWritesShareFilesOnly() {
        QTemporaryDir dir;
        const QByteArray payload = remoteBundlePayload(
            {{QStringLiteral("/etc/samba/smb.conf"), QByteArray("[homes]\n   path = /home\n")},
             {QStringLiteral("/etc/exports.d/shares.exports"), QByteArray("/srv/photos *(rw)\n")},
             {QStringLiteral("/etc/passwd"), QByteArray("nope\n")}});
        QString error;
        QVERIFY(writeRemoteBundle(payload, dir.path(), &error));
        QVERIFY(error.isEmpty());
        QVERIFY(readFile(dir.path() + "/etc/samba/smb.conf").contains("[homes]"));
        QVERIFY(readFile(dir.path() + "/etc/exports.d/shares.exports").contains("/srv/photos"));
        QVERIFY(!QFile::exists(dir.path() + "/etc/passwd"));
        QVERIFY(remoteBundleArgv().join(' ').contains("emit /etc/samba/shares.conf"));
        QCOMPARE(remoteBundleArgv().size(), 5);
    }

    void remoteProbeIsOneShell() {
        class LocalShell : public RemoteLink {
        public:
            int calls = 0;
            CommandResult exec(const QStringList &argv, const QString &, int) override {
                ++calls;
                if (argv != remoteProbeArgv())
                    return {1, {}, "unexpected", false};
                auto script = argv.at(2);
                if (!script.startsWith('\'') || !script.endsWith('\''))
                    return {1, {}, "unquoted", false};
                script = script.mid(1, script.size() - 2);
                script.replace(QStringLiteral("'\\''"), QStringLiteral("'"));
                QProcess process;
                process.start(QStringLiteral("sh"), {QStringLiteral("-c"), script});
                if (!process.waitForFinished(20000))
                    return {124, {}, "timed out", false};
                return {process.exitCode(), QString::fromUtf8(process.readAllStandardOutput()),
                        QString::fromUtf8(process.readAllStandardError()), false};
            }
        };
        LocalShell link;
        const auto need = probeRemote(&link);
        QCOMPARE(link.calls, 1);
        QVERIFY(need.connected);
        QVERIFY(need.profile.family == "arch" || need.profile.family == "debian");
        if (need.sudo)
            QVERIFY(!need.error.contains("passwordless"));
        else
            QVERIFY(need.error.contains("passwordless"));
        QVERIFY(remoteProbeArgv().join(' ').contains("cat /etc/os-release"));
        QVERIFY(remoteProbeArgv().join(' ').contains("sudo -n true"));
        QVERIFY(remoteProbeArgv().join(' ').contains("/usr/bin/python3"));
    }

    void remoteStatusAndS3UseOneShellEach() {
        class LocalShell : public RemoteLink {
        public:
            QVector<QStringList> calls;
            CommandResult exec(const QStringList &argv, const QString &, int) override {
                calls.append(argv);
                if (argv.value(0) != "sh" || argv.size() != 3)
                    return {1, {}, "not a batch", false};
                auto script = argv.at(2);
                if (script.startsWith('\'') && script.endsWith('\'')) {
                    script = script.mid(1, script.size() - 2);
                    script.replace(QStringLiteral("'\\''"), QStringLiteral("'"));
                }
                QProcess process;
                process.start(QStringLiteral("sh"), {QStringLiteral("-c"), script});
                if (!process.waitForFinished(30000))
                    return {124, {}, "timed out", false};
                return {process.exitCode(), QString::fromUtf8(process.readAllStandardOutput()),
                        QString::fromUtf8(process.readAllStandardError()), false};
            }
        };
        QTemporaryDir dir;
        LocalShell link;
        RemoteCommands commands(&link);
        Library library(dir.path(), &commands);
        library.loadStatus();
        QCOMPARE(link.calls.size(), 1);
        QVERIFY(link.calls.first().join(' ').contains("SHARES-BATCH"));
        QVERIFY(link.calls.first().join(' ').contains("systemctl"));
        QVERIFY(link.calls.first().join(' ').contains("tailscale"));
        QVERIFY(library.sambaState.contains(" is "));
        QVERIFY(!library.reachable.isEmpty());

        library.loadS3();
        QCOMPARE(link.calls.size(), 2);
        QVERIFY(link.calls.last().join(' ').contains("mc"));
        QVERIFY(link.calls.last().join(' ').contains("radosgw-admin"));
        QVERIFY(!library.s3State.isEmpty());
    }

    void openSshReusesAControlSocket() {
        const auto plain = sshLaunchArgs(false, "share@files.example.net", 22, false, "/run/user/1000/shares-ssh/%C");
        QVERIFY(plain.contains("ControlMaster=auto"));
        QVERIFY(plain.contains("ControlPersist=600"));
        QVERIFY(plain.contains("ControlPath=/run/user/1000/shares-ssh/%C"));
        QVERIFY(plain.contains("BatchMode=yes"));
        QVERIFY(plain.contains("StrictHostKeyChecking=yes"));
        QVERIFY(!plain.contains("tailscale"));

        const auto trust = sshLaunchArgs(false, "share@files.example.net", 22, true, "/run/user/1000/shares-ssh/%C");
        QVERIFY(trust.contains("StrictHostKeyChecking=accept-new"));
        QVERIFY(!trust.contains("StrictHostKeyChecking=yes"));

        const auto tailscale = sshLaunchArgs(true, "share@files.example.net", 22, false, "/run/user/1000/shares-ssh/%C");
        QCOMPARE(tailscale.first(), QString("tailscale"));
        QVERIFY(!tailscale.join(' ').contains("ControlMaster"));

        const auto skipped = sshLaunchArgs(false, "share@files.example.net", 22, false, QString(90, 'a'));
        QVERIFY(!skipped.join(' ').contains("ControlMaster"));
        const auto empty = sshLaunchArgs(false, "share@files.example.net", 22, false, {});
        QVERIFY(!empty.join(' ').contains("ControlMaster"));
    }

    void themeFallsBack() {
        QTemporaryDir dir;
        Theme theme(dir.path());
        QCOMPARE(theme.accent(), QString("#FFD60A"));
        QCOMPARE(theme.accentForeground(), QString("black"));
    }

    void themeReadsAccent() {
        QTemporaryDir dir;
        QDir(dir.path()).mkpath("theme");
        QFile colors(dir.path() + "/theme/colors.toml");
        QVERIFY(colors.open(QIODevice::WriteOnly));
        colors.write("accent = \"#112233\"\n");
        colors.close();

        Theme theme(dir.path());
        QCOMPARE(theme.accent(), QString("#112233"));
        QCOMPARE(theme.accentForeground(), QString("white"));
    }
};

QTEST_MAIN(SharesTests)
#include "shares_tests.moc"
