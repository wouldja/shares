#pragma once

#include "filepicker.h"
#include "store.h"

#include <QObject>
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

public:
    explicit Backend(const QString &root = {}, Commands *commands = nullptr, FilePicker *picker = nullptr,
                     QObject *parent = nullptr);

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

    Q_INVOKABLE void setProtocol(int protocol);
    Q_INVOKABLE void move(int delta);
    Q_INVOKABLE void select(int id);
    Q_INVOKABLE void toggle(const QString &key);
    Q_INVOKABLE void toggleEnabled();
    Q_INVOKABLE bool create(const QString &name, const QString &path);
    Q_INVOKABLE void browseForCreate(const QString &currentPath = {}, const QString &currentName = {});
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

signals:
    void protocolChanged();
    void modelChanged();
    void historyChanged();
    void errorChanged();
    void dirtyChanged();
    void browsingChanged();
    void createPathChosen(const QString &path);

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
    void copyFromLibrary();
    void touch();
    void setDirty(bool dirty);
    void setError(const QString &error);
    void setBrowsing(bool browsing);
    void connectPicker();
    void acceptPickedPath(const QString &path);
    bool runPlan(const Plan &plan, QString *output = nullptr);
    bool commitWithPkexec(const Plan &plan, QString *error, QString *output);
    bool knownBackend(const QString &backend) const;

    std::unique_ptr<Commands> m_owned;
    Commands *m_commands = nullptr;
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
    std::unique_ptr<FilePicker> m_ownedPicker;
    FilePicker *m_picker = nullptr;
    QVector<Snapshot> m_undo;
    QVector<Snapshot> m_redo;
};
