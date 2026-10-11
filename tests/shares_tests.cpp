#include <QClipboard>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QGuiApplication>
#include <QJsonDocument>
#include <QTemporaryDir>
#include <QtTest>

#include "backend.h"
#include "config.h"
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
