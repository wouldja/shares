#pragma once

#include <QMap>
#include <QString>
#include <QVector>

// File formats Shares reads and writes. Samba and NFS match the on-disk
// files. iSCSI and S3 are the app's own records plus the service tools.

struct SambaShare {
    QString name;
    QString path;
    QString comment;
    bool enabled = true;
    bool guest = false;
    bool readOnly = false;
    bool browsable = true;
    bool inheritPermissions = false;
    bool windowsAcls = false;
    bool shadowCopy = false;
    QString shadowKind = "zfs";
    bool macos = false;
    bool audit = false;
    QString validUsers;
    QString directoryMode;
    bool createPath = false;
    QString quota;
    QString layoutPool;
    bool cephRemount = false;
    QMap<QString, QString> extra;
};

struct SambaGlobal {
    QString workgroup = "WORKGROUP";
    QString serverString;
    QString logLevel = "0";
    bool macos = false;
    QMap<QString, QString> extra;
};

struct SambaConfig {
    SambaGlobal global;
    QVector<SambaShare> shares;
    bool includeRegistry = false;
};

struct NfsClient {
    QString host;
    QString options = "rw,sync,no_subtree_check";
};

struct NfsExport {
    QString path;
    bool enabled = true;
    QVector<NfsClient> clients;
};

struct IscsiDevice {
    QString name;
    QString kind = "fileio";
    QString path;
    QString size;
    bool enabled = true;
    bool writeProtected = false;
};

struct IscsiPortal {
    QString address = "0.0.0.0";
    QString port = "3260";
};

struct IscsiAcl {
    QString initiator;
    QString userid;
    QString password;
};

struct IscsiTarget {
    QString iqn;
    bool enabled = true;
    QString device;
    QVector<IscsiPortal> portals;
    QVector<IscsiAcl> acls;
};

struct IscsiConfig {
    bool clustered = false;
    QString pool = "rbd";
    QVector<IscsiDevice> devices;
    QVector<IscsiTarget> targets;
};

struct S3Bucket {
    QString backend;
    QString name;
    QString usage;
};

struct S3Access {
    QString backend;
    QString name;
    QString kind;
};

struct S3Config {
    QVector<S3Bucket> buckets;
    QVector<S3Access> access;
};

QString sambaShareText(const SambaGlobal &global, const QVector<SambaShare> &shares);
SambaConfig parseSamba(const QString &text);
QString ensureSambaInclude(const QString &smbConf);
QString stripSambaShares(const QString &smbConf);

QString nfsText(const QVector<NfsExport> &exports);
QVector<NfsExport> parseNfs(const QString &text);

QByteArray iscsiJson(const IscsiConfig &config);
IscsiConfig parseIscsiJson(const QByteArray &json, bool *ok = nullptr);

QStringList iscsiApplyCommands(const IscsiConfig &config);
bool commandAllowed(const QStringList &args);
bool shareNameOk(const QString &name);
bool absolutePathOk(const QString &path);
bool nfsHostOk(const QString &host);
bool nfsOptionsOk(const QString &options);
bool accountNameOk(const QString &name);
