#pragma once

#include "config.h"

#include <QByteArray>
#include <QObject>
#include <QStringList>

struct CommandResult {
    int code = 1;
    QString out;
    QString err;
    bool missing = false;
};

class Commands {
public:
    virtual ~Commands();
    // timeoutMs bounds waitForFinished. Probes pass a short value. Saves keep the default.
    // run() has no shared mutable state, so parallelProbes() may call it from several threads.
    virtual CommandResult run(const QString &program, const QStringList &args, const QString &input = {},
                              int timeoutMs = 8000);
    virtual bool parallelProbes() const { return true; }
    virtual int probeTimeoutMs() const { return 2500; }
};

struct PlannedCommand {
    QStringList args;
    QString input;
};

struct Plan {
    QVector<QPair<QString, QString>> files;
    QVector<PlannedCommand> commands;
    QString error;
};

struct Account {
    QString name;
    bool samba = false;
};

// Arch and Debian do not use the same unit or package names. The profile picks
// the names for the computer that will actually run the commands.
struct OsProfile {
    QString family = QStringLiteral("arch");
    QString sambaUnit = QStringLiteral("smb");
    QString nfsUnit = QStringLiteral("nfs-server");
    QString iscsiUnit = QStringLiteral("target");
    QString sambaPackage = QStringLiteral("samba");
    QString nfsPackage = QStringLiteral("nfs-utils");
    QString iscsiPackage = QStringLiteral("targetcli-fb");
};

class Library {
public:
    Library(QString root, Commands *commands);

    // File reads only. The window can show shares before any process starts.
    void loadFiles();
    // Service state, accounts, hostnames, and one tailscale status. No S3 lists, no sessions.
    void loadStatus();
    void loadS3();
    void loadSessions(int protocol);
    void setProfile(const OsProfile &profile) { m_profile = profile; }
    void setRoot(QString root);
    void setCommands(Commands *commands) { m_commands = commands; }
    const OsProfile &profile() const { return m_profile; }

    QString notice;
    QString sambaState;
    QString nfsState;
    QString iscsiState;
    QString s3State;
    QStringList reachable;
    QStringList s3Backends;
    SambaConfig samba;
    QVector<NfsExport> nfs;
    IscsiConfig iscsi;
    S3Config s3;
    QVector<Account> users;
    QStringList sambaSessions;
    QStringList nfsSessions;
    QStringList iscsiSessions;
    // Raw `tailscale status --json` from the latest status probe. Peer parsing
    // reuses this instead of running the command again.
    QString tailscaleStatus;

    // True when smb.conf itself has share sections. Saving then moves them into
    // shares.conf and keeps the previous smb.conf beside it.
    bool smbHadShares = false;
    // RustFS admin origin. Only loopback is accepted, so a privileged save
    // cannot be turned into a request to some other host.
    QString rustfsEndpoint = "http://127.0.0.1:9000";

    Plan plan(const SambaConfig &samba, const QVector<NfsExport> &nfs, const IscsiConfig &iscsi) const;

private:
    QString m_root;
    Commands *m_commands = nullptr;
    OsProfile m_profile;
};

bool loopbackOrigin(const QString &url);
bool applyPlan(const QString &root, const Plan &plan, Commands *commands, QString *error, QString *output = nullptr);
QByteArray planToJson(const Plan &plan);
Plan planFromJson(const QByteArray &bytes, bool *ok = nullptr);
QStringList s3BucketArgs(const QString &backend, const QString &action, const QString &name, const QString &endpoint, QString *error);
QStringList s3AccessArgs(const QString &backend, const QString &action, const QString &name, const QString &secret, QString *error);
QVector<S3Bucket> parseBucketList(const QString &backend, const QString &text);
QStringList parseAccessList(const QString &backend, const QString &text);
QStringList parseSessions(const QString &text);
