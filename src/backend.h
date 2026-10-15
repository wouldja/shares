#pragma once

#include "filepicker.h"
#include "remote.h"
#include "store.h"

#include <QHash>
#include <QObject>
#include <QTemporaryDir>
#include <QVariant>
#include <memory>

// The window's state. File edits stay in memory until Save. Save of the real
// machine goes through pkexec; tests pass a temporary root and a fake runner
// so nothing here touches the live Samba, NFS, or iSCSI configuration.
class Backend : public QObject {
    Q_OBJECT
    Q_PROPERTY(int protocol READ protocol NOTIFY protocolChanged)
    Q_PROPERTY(QString protocolName READ protocolName NOTIFY protocolChanged)
    Q_PROPERTY(QString subtitle READ subtitle NOTIFY modelChanged)
    Q_PROPERTY(QString foot READ foot NOTIFY modelChanged)
    Q_PROPERTY(QString filter READ filter WRITE setFilter NOTIFY modelChanged)
    Q_PROPERTY(QVariantList rows READ rows NOTIFY modelChanged)
    Q_PROPERTY(QVariantMap detail READ detail NOTIFY modelChanged)
    Q_PROPERTY(bool hasSelection READ hasSelection NOTIFY modelChanged)
    Q_PROPERTY(bool canUndo READ canUndo NOTIFY historyChanged)
    Q_PROPERTY(bool canRedo READ canRedo NOTIFY historyChanged)
    Q_PROPERTY(QString error READ error NOTIFY errorChanged)
    Q_PROPERTY(QString notice READ notice NOTIFY modelChanged)
    Q_PROPERTY(QString removeQuestion READ removeQuestion NOTIFY modelChanged)
    Q_PROPERTY(QString removeLabel READ removeLabel NOTIFY protocolChanged)
    Q_PROPERTY(QString keptLine READ keptLine NOTIFY protocolChanged)
    Q_PROPERTY(QVariantList counts READ counts NOTIFY modelChanged)
    Q_PROPERTY(bool dirty READ dirty NOTIFY dirtyChanged)
    Q_PROPERTY(QStringList reachable READ reachable NOTIFY modelChanged)
    Q_PROPERTY(QString userLine READ userLine NOTIFY modelChanged)
    Q_PROPERTY(QString accessLine READ accessLine NOTIFY modelChanged)
    Q_PROPERTY(QString lastOutput READ lastOutput NOTIFY modelChanged)
    Q_PROPERTY(QString createHint READ createHint NOTIFY protocolChanged)
    Q_PROPERTY(bool browsing READ browsing NOTIFY browsingChanged)
    Q_PROPERTY(bool remote READ remote NOTIFY hostChanged)
    Q_PROPERTY(QString browsePath READ browsePath NOTIFY browseChanged)
    Q_PROPERTY(QVariantList browseRows READ browseRows NOTIFY browseChanged)
    Q_PROPERTY(QString browseFile READ browseFile NOTIFY browseChanged)
    Q_PROPERTY(QString hostTitle READ hostTitle NOTIFY hostChanged)
    Q_PROPERTY(QVariantList hosts READ hosts NOTIFY hostChanged)
    Q_PROPERTY(QString needsText READ needsText NOTIFY hostChanged)
    Q_PROPERTY(bool canInstall READ canInstall NOTIFY hostChanged)
    Q_PROPERTY(bool canTrustHost READ canTrustHost NOTIFY hostChanged)
    Q_PROPERTY(bool connecting READ connecting NOTIFY hostChanged)
    Q_PROPERTY(bool smbScanning READ smbScanning NOTIFY smbChanged)
    Q_PROPERTY(QString smbError READ smbError NOTIFY smbChanged)
    Q_PROPERTY(QVariantList smbShares READ smbShares NOTIFY smbChanged)

public:
    explicit Backend(const QString &root = {}, Commands *commands = nullptr, FilePicker *picker = nullptr,
                     RemoteLink *link = nullptr, QObject *parent = nullptr);

    int protocol() const { return m_protocol; }
    QString protocolName() const;
    QString subtitle() const;
    QString foot() const;
    QString filter() const { return m_filter; }
    void setFilter(const QString &filter);
    QVariantList rows() const;
    QVariantMap detail() const;
    bool hasSelection() const { return currentIndex() >= 0; }
    bool canUndo() const { return !m_undo.isEmpty(); }
    bool canRedo() const { return !m_redo.isEmpty(); }
    QString error() const { return m_error; }
    QString notice() const { return m_notice; }
    QString removeQuestion() const;
    QString removeLabel() const;
    QString keptLine() const;
    QVariantList counts() const;
    bool dirty() const { return m_dirty; }
    QStringList reachable() const { return m_reachable; }
    QString userLine() const;
    QString accessLine() const;
    QString lastOutput() const { return m_lastOutput; }
    QString createHint() const;
    bool browsing() const { return m_browsing; }
    bool remote() const { return m_mirror != nullptr; }
    QString browsePath() const { return m_browsePath; }
    QVariantList browseRows() const { return m_browseRows; }
    QString browseFile() const { return m_browseFile; }
    QString hostTitle() const { return m_hostTitle; }
    QVariantList hosts() const { return m_hostRows; }
    QString needsText() const { return m_needsText; }
    bool canInstall() const { return m_canInstall; }
    bool canTrustHost() const { return m_canTrustHost; }
    bool connecting() const { return m_connecting; }
    bool smbScanning() const { return m_smbScanning; }
    QString smbError() const { return m_smbError; }
    QVariantList smbShares() const { return m_smbShares; }
    void setHostsFile(const QString &path);

    Q_INVOKABLE void setProtocol(int protocol);
    Q_INVOKABLE void move(int delta);
    Q_INVOKABLE void select(int id);
    Q_INVOKABLE void toggle(const QString &key);
    Q_INVOKABLE void toggleEnabled();
    Q_INVOKABLE bool create(const QString &name, const QString &path);
    Q_INVOKABLE void browseForCreate(const QString &currentPath = {}, const QString &currentName = {});
    Q_INVOKABLE void browseEnter(int index);
    Q_INVOKABLE void browseUp();
    Q_INVOKABLE bool browseMake(const QString &name);
    Q_INVOKABLE void browseChoose(const QString &fileName);
    Q_INVOKABLE void browseCancel();
    Q_INVOKABLE void removeSelected();
    Q_INVOKABLE void undo();
    Q_INVOKABLE void redo();
    Q_INVOKABLE void copyAddress();
    Q_INVOKABLE void clearError();
    Q_INVOKABLE bool save();
    Q_INVOKABLE void reload();
    Q_INVOKABLE QString editorText() const;
    Q_INVOKABLE bool applyEditor(const QString &text);
    Q_INVOKABLE QString globalText() const;
    Q_INVOKABLE bool applyGlobal(const QString &text);
    Q_INVOKABLE QString exportText() const;
    Q_INVOKABLE bool importText(const QString &text);
    Q_INVOKABLE bool setSambaPassword(const QString &user, const QString &password);
    Q_INVOKABLE bool removeSambaPassword(const QString &user);
    Q_INVOKABLE bool createAccess(const QString &backend, const QString &name, const QString &secret);
    Q_INVOKABLE bool removeAccess(const QString &backend, const QString &name);
    Q_INVOKABLE void refreshHosts();
    Q_INVOKABLE void setHostLogin(const QString &id, const QString &user, const QString &password);
    Q_INVOKABLE bool useHost(const QString &id, const QString &user = {}, const QString &password = {});
    Q_INVOKABLE bool addHost(const QString &user, const QString &host, int port, const QString &password = {});
    Q_INVOKABLE void clearSmbShares();
    Q_INVOKABLE void discoverSmbShares(const QString &host, const QString &user, const QString &password);
    Q_INVOKABLE bool openSmbShare(int index);
    Q_INVOKABLE bool leaveComputer();
    Q_INVOKABLE bool installNeeds();
    Q_INVOKABLE bool trustHost();

signals:
    void protocolChanged();
    void modelChanged();
    void historyChanged();
    void errorChanged();
    void dirtyChanged();
    void browsingChanged();
    void browseChanged();
    void createPathChosen(const QString &path);
    void hostChanged();
    void needsReady();
    void computerReady();
    void smbChanged();

private:
    struct Snapshot {
        SambaConfig samba;
        QVector<NfsExport> nfs;
        IscsiConfig iscsi;
        QVector<int> ids[3];
        int selected[4] = {-1, -1, -1, -1};
        int protocol = 0;
        bool dirty = false;
    };

    int currentIndex() const;
    int indexOf(int protocol, int id) const;
    int countOf(int protocol) const;
    QString nameAt(int index) const;
    QString pathAt(int index) const;
    QVector<int> visibleIndexes() const;
    QStringList addressLines(int index) const;
    QString hostLabel() const;
    QString iqnFor(const QString &name) const;
    Snapshot capture() const;
    void restore(const Snapshot &snapshot);
    void pushUndo();
    void selectNearby(int index);
    void assignIds();
    struct LiveStatus {
        int wave = 0;
        QString sambaState;
        QString nfsState;
        QString iscsiState;
        QStringList reachable;
        QString tailscaleStatus;
        QVector<Account> users;
    };
    struct S3Status {
        int wave = 0;
        QString state;
        QStringList backends;
        S3Config config;
        QString notice;
    };
    struct ConnectResult {
        int wave = 0;
        RemoteNeed need;
        QByteArray bundle;
        QString pullError;
        bool haveBundle = false;
        RemoteHost host;
    };

    void copyFromLibrary();
    void finishReload(int wave, const QString &pullError);
    void scheduleStatus(int wave);
    void applyLiveStatus(const LiveStatus &status);
    void ensureS3();
    void refreshS3();
    void scheduleS3(int wave);
    void applyS3(const S3Status &status);
    void adoptS3();
    void ensureSessions(int protocol);
    void applySessions(int wave, int protocol, const QStringList &sessions);
    void scheduleRemoteReload(int wave);
    bool beginConnect(const RemoteHost &host);
    void applyConnect(const ConnectResult &result, const std::shared_ptr<RemoteLink> &link);
    std::shared_ptr<Commands> liveCommands() const;
    void touch();
    void setDirty(bool dirty);
    void setError(const QString &error);
    void setBrowsing(bool browsing);
    void connectPicker();
    bool beginRemoteBrowse(const QString &path);
    bool openRemoteBrowse(const QString &path);
    static QString childPath(const QString &dir, const QString &name);
    void acceptPickedPath(const QString &path);
    bool runPlan(const Plan &plan, QString *output = nullptr);
    bool commitWithPkexec(const Plan &plan, QString *error, QString *output);
    bool knownBackend(const QString &backend) const;
    QString hostsPath() const;
    void loadSavedHosts();
    void writeSavedHosts() const;
    void publishHosts();
    bool connectRemote(const RemoteHost &host);
    bool connectRemoteUser(const RemoteHost &host);
    void useLocal();
    QString localUser() const;
    RemoteHost hostById(const QString &id) const;

    std::shared_ptr<Commands> m_owned;
    Commands *m_localCommands = nullptr;
    Commands *m_commands = nullptr;
    std::shared_ptr<RemoteLink> m_linkShared;
    RemoteLink *m_link = nullptr;
    RemoteLink *m_injectedLink = nullptr;
    std::shared_ptr<RemoteCommands> m_remoteCommands;
    std::unique_ptr<QTemporaryDir> m_mirror;
    // Real process runs move probes off the caller. Injected test doubles stay
    // on the caller so a test can read the result on the next line.
    bool m_deferProbes = false;
    int m_wave = 0;
    int m_s3Wave = 0;
    int m_hostWave = 0;
    bool m_s3Ready = false;
    bool m_sessionsReady[3] = {false, false, false};
    QString m_appRoot;
    QString m_hostsFile;
    QString m_hostTitle = QStringLiteral("This computer");
    QString m_needsText;
    QString m_pendingUser;
    QString m_pendingHost;
    QString m_pendingPassword;
    int m_pendingPort = 22;
    bool m_pendingTailscaleSsh = false;
    bool m_canInstall = false;
    bool m_canTrustHost = false;
    bool m_connecting = false;
    bool m_trustNextConnect = false;
    QString m_restoreTitle;
    QString m_smbHost;
    QString m_smbError;
    QVariantList m_smbShares;
    int m_smbWave = 0;
    bool m_smbScanning = false;
    QVariantList m_hostRows;
    QVector<RemoteHost> m_saved;
    QVector<RemoteHost> m_peers;
    // Tailscale row logins, keyed by "ts:" + host. Users are written to the
    // host file. Passwords stay in this process and are not written.
    QHash<QString, QString> m_loginUsers;
    QHash<QString, QString> m_loginPasswords;
    OsProfile m_localProfile;
    OsProfile m_remoteProfile;
    QStringList m_neededPackages;
    QString m_root;
    Library m_library;
    SambaConfig m_samba;
    QVector<NfsExport> m_nfs;
    IscsiConfig m_iscsi;
    S3Config m_s3;
    QVector<Account> m_users;
    QStringList m_reachable;
    QStringList m_s3Backends;
    QString m_sambaState;
    QString m_nfsState;
    QString m_iscsiState;
    QString m_s3State;
    QStringList m_sambaSessions;
    QStringList m_nfsSessions;
    QStringList m_iscsiSessions;
    QVector<int> m_ids[4];
    int m_selected[4] = {-1, -1, -1, -1};
    int m_protocol = 0;
    int m_nextId = 1;
    bool m_dirty = false;
    QString m_filter;
    QString m_error;
    QString m_notice;
    QString m_lastOutput;
    bool m_browsing = false;
    QString m_browsePath;
    QVariantList m_browseRows;
    QString m_browseFile;
    std::unique_ptr<FilePicker> m_ownedPicker;
    FilePicker *m_picker = nullptr;
    QVector<Snapshot> m_undo;
    QVector<Snapshot> m_redo;
};
