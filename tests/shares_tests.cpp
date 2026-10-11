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

    CommandResult run(const QString &program, const QStringList &args, const QString &input = {}) override {
        calls.append(QStringList{program} + args);
        inputs.append(input);
        const auto key = (QStringList{program} + args).join(' ');
        if (exact.contains(key))
            return exact.value(key);
        return {0, {}, {}, false};
    }
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
    QVector<QStringList> calls;
    QStringList inputs;
    bool installed = false;

    CommandResult exec(const QStringList &argv, const QString &input, int) override {
        calls.append(argv);
        inputs.append(input);
        const auto key = argv.join(' ');
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
