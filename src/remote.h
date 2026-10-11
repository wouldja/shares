#pragma once

#include "store.h"

#include <QMutex>
#include <QPair>
#include <QVector>

// One computer Shares can manage. Tailscale peers use the tailnet name so the
// SSH connection stays on the tailnet. No password is stored.
struct RemoteHost {
    QString name;
    QString user;
    QString host;
    int port = 22;
    QString via;
    QString address;
    bool tailscaleSsh = false;
};

struct RemoteNeed {
    bool connected = false;
    bool sudo = false;
    bool hostKeyDenied = false;
    QString error;
    OsProfile profile;
    QStringList packages;
    QString command;
};

// Runs one argv on a remote computer. The arguments are already separate, so
// the caller does not build a shell command.
class RemoteLink {
public:
    virtual ~RemoteLink() = default;
    virtual CommandResult exec(const QStringList &argv, const QString &input, int timeoutMs) = 0;
};

class SshLink : public RemoteLink {
public:
    SshLink(QString user, QString host, int port, bool tailscaleSsh);

    CommandResult exec(const QStringList &argv, const QString &input, int timeoutMs) override;
    void trustNextKey();

private:
    QString controlSocket();

    QString m_target;
    int m_port = 22;
    bool m_tailscaleSsh = false;
    bool m_trustNext = false;
    bool m_controlReady = false;
    QString m_controlPath;
    QMutex m_execLock;
};

// Client argv up to, but not including, the remote command. An empty control
// path, a Tailscale SSH destination, or a too-long socket skips multiplexing.
QStringList sshLaunchArgs(bool tailscaleSsh, const QString &target, int port, bool trustNext,
                          const QString &controlPath);

// Library probes (systemctl, hostname, targetcli) go through this while a
// remote computer is selected. File bodies travel separately, on stdin.
class RemoteCommands : public Commands {
public:
    explicit RemoteCommands(RemoteLink *link) : m_link(link) {}

    CommandResult run(const QString &program, const QStringList &args, const QString &input = {},
                      int timeoutMs = 8000) override;
    // Probes share one remote shell. Parallel SSH would open a crowd of sessions
    // and race the host-key trust flag. Later commands reuse the OpenSSH socket.
    bool parallelProbes() const override { return false; }
    bool batchProbes() const override { return true; }
    QHash<QString, CommandResult> runBatch(const QVector<ProbeRequest> &probes) override;
    int probeTimeoutMs() const override { return 8000; }

private:
    RemoteLink *m_link = nullptr;
};

OsProfile profileForRelease(const QString &id, const QString &idLike);
bool remoteTargetOk(const QString &user, const QString &host, int port);
QVector<RemoteHost> tailscalePeers(const QString &json);
QStringList missingPackages(const OsProfile &profile, bool samba, bool nfs, bool iscsi, bool python);
QString installCommand(const OsProfile &profile, const QStringList &packages);
QVector<QStringList> installArgv(const OsProfile &profile, const QStringList &packages);
RemoteNeed probeRemote(RemoteLink *link);
// One remote shell reads the OS, passwordless sudo, and the tool paths.
QStringList remoteProbeArgv();
QStringList remoteProbeToolPaths();
bool pullRemoteFiles(RemoteLink *link, const QString &root, QString *error);
// One remote command reads the bounded share files. The payload is length-prefixed
// text. writeRemoteBundle ignores any path outside that fixed set.
QStringList remoteBundleArgv();
QByteArray remoteBundlePayload(const QVector<QPair<QString, QByteArray>> &files);
bool writeRemoteBundle(const QByteArray &payload, const QString &root, QString *error);
bool installRemotePackages(RemoteLink *link, const OsProfile &profile, const QStringList &packages, QString *error);
bool applyRemotePlan(RemoteLink *link, const QByteArray &helper, const QByteArray &plan, QString *error, QString *output);
