#include "backend.h"

#include <QClipboard>
#include <QCoreApplication>
#include <QDate>
#include <QGuiApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QRegularExpression>
#include <QStandardPaths>

namespace {

QString cleanRoot(QString root) {
    if (root.isEmpty())
        return QString("/");
    if (root.endsWith('/') && root.size() > 1)
        root.chop(1);
    return root;
}

QString yesNo(bool value) { return value ? "yes" : "no"; }

bool asBool(const QString &value) {
    const auto text = value.trimmed().toLower();
    return text == "yes" || text == "true" || text == "1" || text == "on";
}

bool tokenOk(const QString &value) {
    static const QRegularExpression token("^[A-Za-z0-9_./:=+@,%|-]+$");
    return token.match(value).hasMatch() && !value.contains(QStringLiteral(".."));
}

QString baseName(const QString &path) {
    const auto parts = path.split('/', Qt::SkipEmptyParts);
    return parts.isEmpty() ? path : parts.last();
}

QString netbios(const QString &host) {
    QString name = host;
    if (name.endsWith(QStringLiteral(".local")))
        name.chop(6);
    const auto dot = name.indexOf('.');
    if (dot > 0)
        name = name.left(dot);
    return name.isEmpty() ? QStringLiteral("localhost") : name;
}

QVariantMap badge(const QString &text, bool warn) {
    return {{"text", text}, {"warn", warn}};
}

QVariantMap sw(const QString &key, const QString &label, bool on) {
    return {{"key", key}, {"label", label}, {"on", on}};
}

QVariantMap fact(const QString &label, const QString &value) {
    return {{"label", label}, {"value", value}};
}

QString advancedLabel(int count) {
    if (count <= 0)
        return QStringLiteral("none");
    return count == 1 ? QStringLiteral("1 key") : QString("%1 keys").arg(count);
}

bool usersOk(const QString &text) {
    static const QRegularExpression re("^[A-Za-z0-9_@, .$-]*$");
    return re.match(text).hasMatch() && !text.contains(QStringLiteral(".."));
}

bool nfsReadOnly(const NfsExport &exp) {
    if (exp.clients.isEmpty())
        return false;
    for (const auto &client : exp.clients) {
        if (!client.options.split(',').contains(QStringLiteral("ro")))
            return false;
    }
    return true;
}

struct EditorForm {
    QMap<QString, QString> pairs;
    QStringList clients;
    QStringList portals;
    QStringList initiators;
    QStringList advanced;
    bool sawClients = false;
    bool sawPortals = false;
    bool sawInitiators = false;
};

EditorForm parseEditor(const QString &text) {
    EditorForm form;
    enum { Pairs, Clients, Portals, Initiators, Advanced } mode = Pairs;
    for (const auto &raw : text.split('\n')) {
        const auto line = raw.trimmed();
        if (line.isEmpty() || line.startsWith('#'))
            continue;
        if (line == "clients:") {
            mode = Clients;
            form.sawClients = true;
            continue;
        }
        if (line == "portals:") {
            mode = Portals;
            form.sawPortals = true;
            continue;
        }
        if (line == "initiators:") {
            mode = Initiators;
            form.sawInitiators = true;
            continue;
        }
        if (line == "advanced:") {
            mode = Advanced;
            continue;
        }
        if (mode == Clients)
            form.clients << line;
        else if (mode == Portals)
            form.portals << line;
        else if (mode == Initiators)
            form.initiators << line;
        else if (mode == Advanced)
            form.advanced << line;
        else {
            const auto eq = line.indexOf('=');
            if (eq > 0)
                form.pairs.insert(line.left(eq).trimmed().toLower(), line.mid(eq + 1).trimmed());
        }
    }
    return form;
}

bool fillAdvanced(const QStringList &lines, QMap<QString, QString> *extra, QString *error) {
    extra->clear();
    for (const auto &line : lines) {
        const auto eq = line.indexOf('=');
        if (eq <= 0) {
            *error = "An advanced line looks like key = value.";
            return false;
        }
        const auto key = line.left(eq).trimmed().toLower();
        const auto value = line.mid(eq + 1).trimmed();
        if (key == "include" || key.contains('\n') || value.contains('\n')) {
            *error = "An advanced key cannot include another file.";
            return false;
        }
        static const QRegularExpression keyOk("^[a-z0-9_ .:*-]+$");
        if (!keyOk.match(key).hasMatch()) {
            *error = "An advanced key uses a character Shares will not write.";
            return false;
        }
        extra->insert(key, value);
    }
    return true;
}

QString joinSessions(const QStringList &sessions) {
    if (sessions.isEmpty())
        return QStringLiteral("quiet");
    return sessions.mid(0, 6).join('\n');
}

} // namespace

Backend::Backend(const QString &root, Commands *commands, QObject *parent)
    : QObject(parent), m_owned(commands ? nullptr : std::make_unique<Commands>()),
      m_commands(commands ? commands : m_owned.get()), m_root(cleanRoot(root)), m_library(m_root, m_commands) {
    reload();
}

void Backend::reload() {
    m_library.load();
    copyFromLibrary();
    m_filter.clear();
    m_undo.clear();
    m_redo.clear();
    setError({});
    emit protocolChanged();
    emit dirtyChanged();
    emit historyChanged();
    touch();
}

void Backend::copyFromLibrary() {
    m_samba = m_library.samba;
    m_nfs = m_library.nfs;
    m_iscsi = m_library.iscsi;
    m_s3 = m_library.s3;
    m_users = m_library.users;
    m_reachable = m_library.reachable;
    m_s3Backends = m_library.s3Backends;
    m_sambaState = m_library.sambaState;
    m_nfsState = m_library.nfsState;
    m_iscsiState = m_library.iscsiState;
    m_s3State = m_library.s3State;
    m_sambaSessions = m_library.sambaSessions;
    m_nfsSessions = m_library.nfsSessions;
    m_iscsiSessions = m_library.iscsiSessions;
    m_notice = m_library.notice;
    m_dirty = m_library.smbHadShares;
    m_lastOutput.clear();
    assignIds();
}

void Backend::assignIds() {
    const int counts[] = {int(m_samba.shares.size()), int(m_nfs.size()), int(m_iscsi.targets.size()), int(m_s3.buckets.size())};
    for (int protocol = 0; protocol < 4; ++protocol) {
        m_ids[protocol].clear();
        for (int i = 0; i < counts[protocol]; ++i)
            m_ids[protocol].append(m_nextId++);
        m_selected[protocol] = m_ids[protocol].isEmpty() ? -1 : m_ids[protocol].first();
    }
}

int Backend::indexOf(int protocol, int id) const {
    for (int i = 0; i < m_ids[protocol].size(); ++i) {
        if (m_ids[protocol].at(i) == id)
            return i;
    }
    return -1;
}

int Backend::currentIndex() const { return indexOf(m_protocol, m_selected[m_protocol]); }

int Backend::countOf(int protocol) const {
    if (protocol == 0)
        return m_samba.shares.size();
    if (protocol == 1)
        return m_nfs.size();
    if (protocol == 2)
        return m_iscsi.targets.size();
    return m_s3.buckets.size();
}

QString Backend::nameAt(int index) const {
    if (m_protocol == 0)
        return m_samba.shares.at(index).name;
    if (m_protocol == 1)
        return baseName(m_nfs.at(index).path);
    if (m_protocol == 2)
        return m_iscsi.targets.at(index).device.isEmpty() ? m_iscsi.targets.at(index).iqn : m_iscsi.targets.at(index).device;
    return m_s3.buckets.at(index).name;
}

QString Backend::pathAt(int index) const {
    if (m_protocol == 0)
        return m_samba.shares.at(index).path;
    if (m_protocol == 1)
        return m_nfs.at(index).path;
    if (m_protocol == 2)
        return m_iscsi.targets.at(index).iqn;
    return m_s3.buckets.at(index).backend;
}

QVector<int> Backend::visibleIndexes() const {
    QVector<int> indexes;
    for (int i = 0; i < countOf(m_protocol); ++i) {
        if (m_filter.isEmpty() || nameAt(i).contains(m_filter, Qt::CaseInsensitive) || pathAt(i).contains(m_filter, Qt::CaseInsensitive))
            indexes.append(i);
    }
    return indexes;
}

QString Backend::protocolName() const {
    switch (m_protocol) {
    case 1:
        return QStringLiteral("NFS");
    case 2:
        return QStringLiteral("iSCSI");
    case 3:
        return QStringLiteral("S3");
    default:
        return QStringLiteral("Samba");
    }
}

QString Backend::subtitle() const {
    switch (m_protocol) {
    case 1:
        return QString("%1 exports · %2").arg(m_nfs.size()).arg(m_nfsState);
    case 2:
        return QString("%1 targets · %2").arg(m_iscsi.targets.size()).arg(m_iscsiState);
    case 3:
        return QString("%1 buckets · %2").arg(m_s3.buckets.size()).arg(m_s3State);
    default:
        return QString("%1 shares · %2").arg(m_samba.shares.size()).arg(m_sambaState);
    }
}

QString Backend::foot() const {
    switch (m_protocol) {
    case 1:
        return QString("/etc/exports.d/shares.exports\n%1").arg(m_nfsState);
    case 2:
        return QString("Mode %1\n%2").arg(m_iscsi.clustered ? QStringLiteral("clustered") : QStringLiteral("single server"), m_iscsiState);
    case 3:
        return m_s3State;
    default:
        return QString("Workgroup %1\n%2").arg(m_samba.global.workgroup, m_sambaState);
    }
}

QString Backend::userLine() const {
    if (m_users.isEmpty())
        return QStringLiteral("No local accounts were listed.");
    QStringList lines;
    for (const auto &user : m_users)
        lines << user.name + (user.samba ? QStringLiteral(" · Samba") : QString());
    return lines.join('\n');
}

QString Backend::accessLine() const {
    if (m_s3.access.isEmpty())
        return QStringLiteral("No access keys are listed.");
    QStringList lines;
    for (const auto &access : m_s3.access)
        lines << access.backend + " · " + access.name;
    return lines.join('\n');
}

QString Backend::createHint() const {
    switch (m_protocol) {
    case 1:
        return QStringLiteral("Adds an export for every client (*). Change the clients with Edit, then Save.");
    case 2:
        return QStringLiteral("Save creates the disk image. Removing the target leaves that image in place.");
    case 3:
        return QStringLiteral("Creates the bucket on the named backend now. Ceph buckets are created through the S3 API, not here.");
    default:
        return QStringLiteral("Adds a share. The name and folder stay fixed after this. Save writes it.");
    }
}

QString Backend::removeLabel() const {
    switch (m_protocol) {
    case 1:
        return QStringLiteral("Remove export");
    case 2:
        return QStringLiteral("Remove target");
    case 3:
        return QStringLiteral("Remove bucket");
    default:
        return QStringLiteral("Remove share");
    }
}

QString Backend::keptLine() const {
    switch (m_protocol) {
    case 1:
        return QStringLiteral("Removes the export only. The folder stays.");
    case 2:
        return QStringLiteral("Removes the target only. The disk image stays.");
    case 3:
        return QStringLiteral("Deletes an empty bucket on the S3 service. Objects are left when the service refuses.");
    default:
        return QStringLiteral("Removes the share only. The folder stays.");
    }
}

QString Backend::removeQuestion() const {
    const int index = currentIndex();
    if (index < 0)
        return {};
    return QString("Remove %1?\n%2").arg(nameAt(index), keptLine());
}

QVariantList Backend::counts() const {
    return {m_samba.shares.size(), m_nfs.size(), m_iscsi.targets.size(), m_s3.buckets.size()};
}

QString Backend::hostLabel() const {
    QString host = m_reachable.isEmpty() ? QStringLiteral("host") : m_reachable.first();
    if (host.endsWith(QStringLiteral(".local")))
        host.chop(6);
    const auto dot = host.indexOf('.');
    if (dot > 0)
        host = host.left(dot);
    host.replace(QRegularExpression("[^A-Za-z0-9-]"), "-");
    return host.isEmpty() ? QStringLiteral("host") : host;
}

QString Backend::iqnFor(const QString &name) const {
    const auto date = QDate::currentDate();
    return QString("iqn.%1-%2.local.%3:%4")
        .arg(date.year(), 4, 10, QChar('0'))
        .arg(date.month(), 2, 10, QChar('0'))
        .arg(hostLabel(), name);
}

QStringList Backend::addressLines(int index) const {
    const auto hosts = m_reachable.isEmpty() ? QStringList{QStringLiteral("localhost")} : m_reachable;
    QStringList lines;
    if (m_protocol == 0) {
        const auto name = m_samba.shares.at(index).name;
        for (const auto &host : hosts)
            lines << "smb://" + host + "/" + name;
        lines << "\\\\" + netbios(hosts.first()) + "\\" + name;
    } else if (m_protocol == 1) {
        const auto path = m_nfs.at(index).path;
        for (const auto &host : hosts) {
            lines << host + ":" + path;
            lines << "nfs://" + host + path;
        }
    } else if (m_protocol == 2) {
        const auto &target = m_iscsi.targets.at(index);
        const auto port = target.portals.isEmpty() ? QStringLiteral("3260") : target.portals.first().port;
        const auto listen = target.portals.isEmpty() ? QStringLiteral("0.0.0.0") : target.portals.first().address;
        if (listen == "0.0.0.0" || listen == "::") {
            for (const auto &host : hosts)
                lines << host + ":" + port;
        } else {
            lines << listen + ":" + port;
        }
    } else {
        lines << "s3://" + m_s3.buckets.at(index).name;
    }
    return lines;
}

QVariantList Backend::rows() const {
    QVariantList list;
    for (const int index : visibleIndexes()) {
        QVariantList badges;
        QString meta = QStringLiteral("quiet");
        bool enabled = true;
        if (m_protocol == 0) {
            const auto &share = m_samba.shares.at(index);
            enabled = share.enabled;
            if (share.guest)
                badges << badge("Guest", true);
            if (share.readOnly)
                badges << badge("Read only", false);
            meta = enabled ? QStringLiteral("quiet") : QStringLiteral("disabled");
        } else if (m_protocol == 1) {
            const auto &exp = m_nfs.at(index);
            enabled = exp.enabled;
            if (nfsReadOnly(exp))
                badges << badge("Read only", false);
            meta = enabled ? QString("%1 clients").arg(exp.clients.size()) : QStringLiteral("disabled");
        } else if (m_protocol == 2) {
            const auto &target = m_iscsi.targets.at(index);
            enabled = target.enabled;
            QString size;
            for (const auto &device : m_iscsi.devices) {
                if (device.name == target.device) {
                    size = device.size;
                    if (device.writeProtected)
                        badges << badge("Read only", false);
                }
            }
            meta = !enabled ? QStringLiteral("disabled") : size;
        } else {
            meta = m_s3.buckets.at(index).backend;
        }
        list << QVariantMap{{"id", m_ids[m_protocol].at(index)},
                            {"name", nameAt(index)},
                            {"path", pathAt(index)},
                            {"enabled", enabled},
                            {"meta", meta},
                            {"badges", badges}};
    }
    return list;
}

QVariantMap Backend::detail() const {
    const int index = currentIndex();
    if (index < 0)
        return {};
    QVariantList switches;
    QVariantList facts;
    QString advanced = QStringLiteral("none");
    if (m_protocol == 0) {
        const auto &share = m_samba.shares.at(index);
        switches = {sw("guest", "Guest", share.guest),
                    sw("readOnly", "Read only", share.readOnly),
                    sw("browsable", "Browsable", share.browsable),
                    sw("inheritPermissions", "Inherit permissions", share.inheritPermissions),
                    sw("windowsAcls", "Windows ACLs", share.windowsAcls),
                    sw("shadowCopy", "Shadow copy", share.shadowCopy),
                    sw("macos", "MacOS", share.macos),
                    sw("audit", "Audit", share.audit)};
        const auto who = share.guest ? QStringLiteral("Guest")
                         : share.validUsers.isEmpty() ? QStringLiteral("Any authenticated user")
                                                      : share.validUsers;
        facts = {fact("WHO", who), fact("CONNECTED", joinSessions(m_sambaSessions))};
        if (!share.comment.isEmpty())
            facts << fact("COMMENT", share.comment);
        if (!share.directoryMode.isEmpty() || share.createPath)
            facts << fact("FOLDER", (share.directoryMode.isEmpty() ? QString() : share.directoryMode + " ")
                                     + (share.createPath ? QStringLiteral("create if missing") : QString()));
        if (!share.quota.isEmpty())
            facts << fact("QUOTA", share.quota);
        if (!share.layoutPool.isEmpty())
            facts << fact("LAYOUT POOL", share.layoutPool);
        if (share.cephRemount)
            facts << fact("CEPH", "remount");
        advanced = advancedLabel(share.extra.size());
    } else if (m_protocol == 1) {
        const auto &exp = m_nfs.at(index);
        switches = {sw("readOnly", "Read only", nfsReadOnly(exp))};
        QStringList clients;
        for (const auto &client : exp.clients)
            clients << client.host + " · " + client.options;
        facts = {fact("CLIENTS", clients.isEmpty() ? QStringLiteral("none") : clients.join('\n')),
                 fact("CONNECTED", joinSessions(m_nfsSessions))};
        advanced = QStringLiteral("clients");
    } else if (m_protocol == 2) {
        const auto &target = m_iscsi.targets.at(index);
        const IscsiDevice *device = nullptr;
        for (const auto &item : m_iscsi.devices) {
            if (item.name == target.device)
                device = &item;
        }
        switches = {sw("writeProtected", "Write protected", device && device->writeProtected)};
        if (device)
            facts << fact("BACKING", device->kind + " · " + device->path + (device->size.isEmpty() ? QString() : " · " + device->size));
        QStringList portals;
        for (const auto &portal : target.portals)
            portals << portal.address + ":" + portal.port;
        facts << fact("PORTAL", portals.isEmpty() ? QStringLiteral("none") : portals.join('\n'));
        QStringList initiators;
        QString chap = QStringLiteral("off");
        for (const auto &acl : target.acls) {
            initiators << acl.initiator;
            if (!acl.userid.isEmpty())
                chap = acl.userid;
        }
        facts << fact("INITIATOR", initiators.isEmpty() ? QStringLiteral("No initiator limit") : initiators.join('\n'));
        facts << fact("CHAP", chap);
        facts << fact("CONNECTED", joinSessions(m_iscsiSessions));
        facts << fact("MODE", m_iscsi.clustered ? QStringLiteral("clustered") : QStringLiteral("single server"));
        advanced = QStringLiteral("portal, CHAP");
    } else {
        const auto &bucket = m_s3.buckets.at(index);
        facts << fact("BACKEND", bucket.backend);
        facts << fact("USAGE", bucket.usage.isEmpty() ? QStringLiteral("not reported") : bucket.usage);
        QStringList names;
        for (const auto &access : m_s3.access) {
            if (access.backend == bucket.backend)
                names << access.name;
        }
        facts << fact("ACCESS", names.isEmpty() ? QStringLiteral("none") : names.join('\n'));
        advanced = QStringLiteral("access");
    }
    return {{"id", m_ids[m_protocol].at(index)},
            {"name", nameAt(index)},
            {"path", pathAt(index)},
            {"addresses", addressLines(index)},
            {"switches", switches},
            {"facts", facts},
            {"advanced", advanced}};
}

void Backend::setFilter(const QString &filter) {
    if (m_filter == filter)
        return;
    m_filter = filter;
    touch();
}

void Backend::setProtocol(int protocol) {
    protocol = qBound(0, protocol, 3);
    if (protocol == m_protocol)
        return;
    m_protocol = protocol;
    m_filter.clear();
    emit protocolChanged();
    touch();
}

void Backend::move(int delta) {
    const auto visible = visibleIndexes();
    if (visible.isEmpty())
        return;
    int pos = visible.indexOf(currentIndex());
    if (pos < 0)
        pos = delta > 0 ? 0 : visible.size() - 1;
    else
        pos = (pos + delta) % visible.size();
    if (pos < 0)
        pos += visible.size();
    m_selected[m_protocol] = m_ids[m_protocol].at(visible.at(pos));
    touch();
}

void Backend::select(int id) {
    if (indexOf(m_protocol, id) < 0)
        return;
    m_selected[m_protocol] = id;
    touch();
}

void Backend::toggle(const QString &key) {
    const int index = currentIndex();
    if (index < 0)
        return;
    pushUndo();
    bool changed = false;
    if (m_protocol == 0) {
        auto &share = m_samba.shares[index];
        if (key == "guest")
            share.guest = !share.guest, changed = true;
        else if (key == "readOnly")
            share.readOnly = !share.readOnly, changed = true;
        else if (key == "browsable")
            share.browsable = !share.browsable, changed = true;
        else if (key == "inheritPermissions")
            share.inheritPermissions = !share.inheritPermissions, changed = true;
        else if (key == "windowsAcls")
            share.windowsAcls = !share.windowsAcls, changed = true;
        else if (key == "shadowCopy")
            share.shadowCopy = !share.shadowCopy, changed = true;
        else if (key == "macos")
            share.macos = !share.macos, changed = true;
        else if (key == "audit")
            share.audit = !share.audit, changed = true;
    } else if (m_protocol == 1 && key == "readOnly") {
        auto &exp = m_nfs[index];
        const bool on = !nfsReadOnly(exp);
        for (auto &client : exp.clients) {
            auto options = client.options.split(',', Qt::SkipEmptyParts);
            options.removeAll(QStringLiteral("ro"));
            options.removeAll(QStringLiteral("rw"));
            options.prepend(on ? QStringLiteral("ro") : QStringLiteral("rw"));
            client.options = options.join(',');
        }
        changed = true;
    } else if (m_protocol == 2 && key == "writeProtected") {
        const auto deviceName = m_iscsi.targets.at(index).device;
        for (auto &device : m_iscsi.devices) {
            if (device.name == deviceName) {
                device.writeProtected = !device.writeProtected;
                changed = true;
            }
        }
    }
    if (!changed) {
        if (!m_undo.isEmpty())
            m_undo.removeLast();
        emit historyChanged();
        return;
    }
    setDirty(true);
    touch();
}

void Backend::toggleEnabled() {
    const int index = currentIndex();
    if (index < 0 || m_protocol == 3)
        return;
    pushUndo();
    if (m_protocol == 0)
        m_samba.shares[index].enabled = !m_samba.shares[index].enabled;
    else if (m_protocol == 1)
        m_nfs[index].enabled = !m_nfs[index].enabled;
    else
        m_iscsi.targets[index].enabled = !m_iscsi.targets[index].enabled;
    setDirty(true);
    touch();
}

bool Backend::create(const QString &name, const QString &path) {
    const auto trimmedName = name.trimmed();
    const auto trimmedPath = path.trimmed();
    if (m_protocol == 3) {
        const auto backend = trimmedPath.isEmpty() && m_s3Backends.size() == 1 ? m_s3Backends.first() : trimmedPath;
        if (!knownBackend(backend)) {
            setError(m_s3Backends.isEmpty() ? QStringLiteral("No S3 backend is installed.") : QStringLiteral("Name the backend: minio, garage, ceph, or rustfs."));
            return false;
        }
        QString error;
        const auto args = s3BucketArgs(backend, "create", trimmedName, m_library.rustfsEndpoint, &error);
        if (args.isEmpty()) {
            setError(error);
            return false;
        }
        Plan plan;
        plan.commands.append({args, {}});
        if (!runPlan(plan))
            return false;
        m_s3.buckets.append({backend, trimmedName, {}});
        m_ids[3].append(m_nextId++);
        m_selected[3] = m_ids[3].last();
        touch();
        return true;
    }
    if (m_protocol == 0) {
        if (trimmedName.isEmpty() || trimmedPath.isEmpty()) {
            setError(QStringLiteral("A share needs a name and a path."));
            return false;
        }
        if (!shareNameOk(trimmedName)) {
            setError(QStringLiteral("Share names use letters, numbers, and . _ $ -."));
            return false;
        }
        if (!absolutePathOk(trimmedPath)) {
            setError(QStringLiteral("A share path has to be an absolute path."));
            return false;
        }
        for (const auto &share : m_samba.shares) {
            if (share.name == trimmedName) {
                setError(QStringLiteral("A share with that name already exists."));
                return false;
            }
        }
        pushUndo();
        SambaShare share;
        share.name = trimmedName;
        share.path = trimmedPath;
        m_samba.shares.append(share);
        m_ids[0].append(m_nextId++);
        m_selected[0] = m_ids[0].last();
    } else if (m_protocol == 1) {
        if (!absolutePathOk(trimmedPath)) {
            setError(QStringLiteral("An export needs an absolute folder."));
            return false;
        }
        for (const auto &exp : m_nfs) {
            if (exp.path == trimmedPath) {
                setError(QStringLiteral("That folder is already exported."));
                return false;
            }
        }
        pushUndo();
        NfsExport exp;
        exp.path = trimmedPath;
        exp.clients.append({QStringLiteral("*"), QStringLiteral("rw,sync,no_subtree_check")});
        m_nfs.append(exp);
        m_ids[1].append(m_nextId++);
        m_selected[1] = m_ids[1].last();
    } else {
        if (trimmedName.isEmpty() || trimmedPath.isEmpty()) {
            setError(QStringLiteral("A target needs a name and a disk image."));
            return false;
        }
        if (!shareNameOk(trimmedName)) {
            setError(QStringLiteral("Target names use letters, numbers, and . _ $ -."));
            return false;
        }
        if (!absolutePathOk(trimmedPath)) {
            setError(QStringLiteral("The disk image path has to be an absolute path."));
            return false;
        }
        for (const auto &device : m_iscsi.devices) {
            if (device.name == trimmedName) {
                setError(QStringLiteral("A target with that name already exists."));
                return false;
            }
        }
        pushUndo();
        IscsiDevice device;
        device.name = trimmedName;
        device.path = trimmedPath;
        device.size = QStringLiteral("1G");
        m_iscsi.devices.append(device);
        IscsiTarget target;
        target.iqn = iqnFor(trimmedName);
        target.device = trimmedName;
        target.portals.append({QStringLiteral("0.0.0.0"), QStringLiteral("3260")});
        m_iscsi.targets.append(target);
        m_ids[2].append(m_nextId++);
        m_selected[2] = m_ids[2].last();
    }
    setDirty(true);
    setError({});
    touch();
    return true;
}

void Backend::selectNearby(int index) {
    if (m_ids[m_protocol].isEmpty()) {
        m_selected[m_protocol] = -1;
        return;
    }
    if (index >= m_ids[m_protocol].size())
        index = m_ids[m_protocol].size() - 1;
    if (index < 0)
        index = 0;
    m_selected[m_protocol] = m_ids[m_protocol].at(index);
}

void Backend::removeSelected() {
    const int index = currentIndex();
    if (index < 0)
        return;
    if (m_protocol == 3) {
        const auto bucket = m_s3.buckets.at(index);
        QString error;
        const auto args = s3BucketArgs(bucket.backend, "delete", bucket.name, m_library.rustfsEndpoint, &error);
        if (args.isEmpty()) {
            setError(error);
            return;
        }
        Plan plan;
        plan.commands.append({args, {}});
        if (!runPlan(plan))
            return;
        m_s3.buckets.removeAt(index);
        m_ids[3].removeAt(index);
        selectNearby(index);
        touch();
        return;
    }
    pushUndo();
    if (m_protocol == 0) {
        m_samba.shares.removeAt(index);
        m_ids[0].removeAt(index);
    } else if (m_protocol == 1) {
        m_nfs.removeAt(index);
        m_ids[1].removeAt(index);
    } else {
        const auto deviceName = m_iscsi.targets.at(index).device;
        m_iscsi.targets.removeAt(index);
        m_ids[2].removeAt(index);
        bool used = false;
        for (const auto &target : m_iscsi.targets) {
            if (target.device == deviceName)
                used = true;
        }
        if (!used) {
            for (int i = 0; i < m_iscsi.devices.size(); ++i) {
                if (m_iscsi.devices.at(i).name == deviceName)
                    m_iscsi.devices.removeAt(i);
            }
        }
    }
    selectNearby(index);
    setDirty(true);
    touch();
}

void Backend::undo() {
    if (m_undo.isEmpty())
        return;
    m_redo.append(capture());
    restore(m_undo.takeLast());
}

void Backend::redo() {
    if (m_redo.isEmpty())
        return;
    m_undo.append(capture());
    restore(m_redo.takeLast());
}

Backend::Snapshot Backend::capture() const {
    Snapshot snapshot;
    snapshot.samba = m_samba;
    snapshot.nfs = m_nfs;
    snapshot.iscsi = m_iscsi;
    for (int i = 0; i < 3; ++i)
        snapshot.ids[i] = m_ids[i];
    for (int i = 0; i < 4; ++i)
        snapshot.selected[i] = m_selected[i];
    snapshot.protocol = m_protocol;
    snapshot.dirty = m_dirty;
    return snapshot;
}

void Backend::restore(const Snapshot &snapshot) {
    const int protocol = m_protocol;
    const auto s3ids = m_ids[3];
    const int s3selected = m_selected[3];
    m_samba = snapshot.samba;
    m_nfs = snapshot.nfs;
    m_iscsi = snapshot.iscsi;
    for (int i = 0; i < 3; ++i)
        m_ids[i] = snapshot.ids[i];
    m_ids[3] = s3ids;
    for (int i = 0; i < 4; ++i)
        m_selected[i] = snapshot.selected[i];
    m_selected[3] = s3selected;
    m_protocol = snapshot.protocol;
    setDirty(snapshot.dirty);
    if (protocol != m_protocol)
        emit protocolChanged();
    emit historyChanged();
    touch();
}

void Backend::pushUndo() {
    m_undo.append(capture());
    if (m_undo.size() > 50)
        m_undo.removeFirst();
    m_redo.clear();
    emit historyChanged();
}

void Backend::copyAddress() {
    const int index = currentIndex();
    if (index < 0) {
        setError(QStringLiteral("There is no address to copy."));
        return;
    }
    const auto lines = addressLines(index);
    if (lines.isEmpty() || QGuiApplication::clipboard() == nullptr) {
        setError(QStringLiteral("There is no address to copy."));
        return;
    }
    QGuiApplication::clipboard()->setText(lines.first());
}

void Backend::clearError() { setError({}); }

bool Backend::save() {
    if (!m_dirty)
        return true;
    const auto plan = m_library.plan(m_samba, m_nfs, m_iscsi);
    if (!runPlan(plan))
        return false;
    m_library.samba = m_samba;
    m_library.nfs = m_nfs;
    m_library.iscsi = m_iscsi;
    m_library.smbHadShares = false;
    setDirty(false);
    return true;
}

QString Backend::editorText() const {
    const int index = currentIndex();
    if (index < 0)
        return {};
    if (m_protocol == 0) {
        const auto &share = m_samba.shares.at(index);
        QString text;
        text += "comment=" + share.comment + "\n";
        text += "valid users=" + share.validUsers + "\n";
        text += "directory mode=" + share.directoryMode + "\n";
        text += "create path=" + yesNo(share.createPath) + "\n";
        text += "quota=" + share.quota + "\n";
        text += "layout pool=" + share.layoutPool + "\n";
        text += "shadow kind=" + share.shadowKind + "\n";
        text += "windows acls=" + yesNo(share.windowsAcls) + "\n";
        text += "shadow copy=" + yesNo(share.shadowCopy) + "\n";
        text += "macos=" + yesNo(share.macos) + "\n";
        text += "audit=" + yesNo(share.audit) + "\n";
        text += "ceph remount=" + yesNo(share.cephRemount) + "\n";
        text += "advanced:\n";
        for (auto it = share.extra.cbegin(); it != share.extra.cend(); ++it)
            text += it.key() + " = " + it.value() + "\n";
        return text;
    }
    if (m_protocol == 1) {
        QString text = "clients:\n";
        for (const auto &client : m_nfs.at(index).clients)
            text += client.host + " " + client.options + "\n";
        return text;
    }
    if (m_protocol == 2) {
        const auto &target = m_iscsi.targets.at(index);
        const IscsiDevice *device = nullptr;
        for (const auto &item : m_iscsi.devices) {
            if (item.name == target.device)
                device = &item;
        }
        QString text;
        text += "size=" + (device ? device->size : QString()) + "\n";
        text += "kind=" + (device ? device->kind : QStringLiteral("fileio")) + "\n";
        text += "write protected=" + yesNo(device && device->writeProtected) + "\n";
        text += "clustered=" + yesNo(m_iscsi.clustered) + "\n";
        text += "pool=" + m_iscsi.pool + "\n";
        text += "portals:\n";
        for (const auto &portal : target.portals)
            text += portal.address + " " + portal.port + "\n";
        text += "initiators:\n";
        for (const auto &acl : target.acls)
            text += acl.initiator + (acl.userid.isEmpty() ? QString() : " " + acl.userid)
                + (acl.password.isEmpty() ? QString() : " " + acl.password) + "\n";
        return text;
    }
    return QStringLiteral("# Create and remove buckets from the list.\n# Access keys are under U.\n");
}

bool Backend::applyEditor(const QString &text) {
    const int index = currentIndex();
    if (index < 0) {
        setError(QStringLiteral("Select a row first."));
        return false;
    }
    if (m_protocol == 3) {
        setError(QStringLiteral("Bucket settings are on the S3 service. Create and remove buckets from this list."));
        return false;
    }
    const auto form = parseEditor(text);
    auto samba = m_samba;
    auto nfs = m_nfs;
    auto iscsi = m_iscsi;
    QString error;
    if (m_protocol == 0) {
        auto &share = samba.shares[index];
        if (form.pairs.contains("comment")) {
            if (form.pairs.value("comment").contains(']')) {
                setError(QStringLiteral("A comment cannot contain ]."));
                return false;
            }
            share.comment = form.pairs.value("comment");
        }
        if (form.pairs.contains("valid users")) {
            if (!usersOk(form.pairs.value("valid users"))) {
                setError(QStringLiteral("Valid users are account names separated by spaces."));
                return false;
            }
            share.validUsers = form.pairs.value("valid users");
        }
        if (form.pairs.contains("directory mode")) {
            static const QRegularExpression mode("^$|^0[0-7]{3}$");
            if (!mode.match(form.pairs.value("directory mode")).hasMatch()) {
                setError(QStringLiteral("Directory mode looks like 0755."));
                return false;
            }
            share.directoryMode = form.pairs.value("directory mode");
        }
        if (form.pairs.contains("create path"))
            share.createPath = asBool(form.pairs.value("create path"));
        if (form.pairs.contains("quota"))
            share.quota = form.pairs.value("quota");
        if (form.pairs.contains("layout pool"))
            share.layoutPool = form.pairs.value("layout pool");
        if (form.pairs.contains("shadow kind")) {
            const auto kind = form.pairs.value("shadow kind");
            if (kind != "zfs" && kind != "ceph") {
                setError(QStringLiteral("Shadow copy is zfs or ceph."));
                return false;
            }
            share.shadowKind = kind;
        }
        if (form.pairs.contains("windows acls"))
            share.windowsAcls = asBool(form.pairs.value("windows acls"));
        if (form.pairs.contains("shadow copy"))
            share.shadowCopy = asBool(form.pairs.value("shadow copy"));
        if (form.pairs.contains("macos"))
            share.macos = asBool(form.pairs.value("macos"));
        if (form.pairs.contains("audit"))
            share.audit = asBool(form.pairs.value("audit"));
        if (form.pairs.contains("ceph remount"))
            share.cephRemount = asBool(form.pairs.value("ceph remount"));
        if (!fillAdvanced(form.advanced, &share.extra, &error)) {
            setError(error);
            return false;
        }
    } else if (m_protocol == 1) {
        if (!form.sawClients || form.clients.isEmpty()) {
            setError(QStringLiteral("An export needs at least one client."));
            return false;
        }
        QVector<NfsClient> clients;
        for (const auto &line : form.clients) {
            const auto host = line.section(' ', 0, 0);
            auto options = line.section(' ', 1).trimmed();
            if (options.isEmpty())
                options = QStringLiteral("rw,sync,no_subtree_check");
            if (!nfsHostOk(host) || !nfsOptionsOk(options)) {
                setError(QStringLiteral("An NFS client or its options use a character Shares will not write."));
                return false;
            }
            clients.append({host, options});
        }
        nfs[index].clients = clients;
    } else {
        auto &target = iscsi.targets[index];
        IscsiDevice *device = nullptr;
        for (auto &item : iscsi.devices) {
            if (item.name == target.device)
                device = &item;
        }
        if (form.pairs.contains("kind") && device) {
            const auto kind = form.pairs.value("kind");
            if (kind != "fileio" && kind != "block") {
                setError(QStringLiteral("A backing image is fileio or block."));
                return false;
            }
            device->kind = kind;
        }
        if (form.pairs.contains("size") && device) {
            static const QRegularExpression size("^$|^[0-9]+[MGT]?$");
            if (!size.match(form.pairs.value("size")).hasMatch()) {
                setError(QStringLiteral("Size looks like 1G."));
                return false;
            }
            device->size = form.pairs.value("size");
        }
        if (form.pairs.contains("write protected") && device)
            device->writeProtected = asBool(form.pairs.value("write protected"));
        if (form.pairs.contains("pool")) {
            if (!shareNameOk(form.pairs.value("pool"))) {
                setError(QStringLiteral("The pool name uses letters and numbers."));
                return false;
            }
            iscsi.pool = form.pairs.value("pool");
        }
        if (form.pairs.contains("clustered")) {
            const bool clustered = asBool(form.pairs.value("clustered"));
            if (clustered != iscsi.clustered && (!iscsi.targets.isEmpty() || !iscsi.devices.isEmpty())) {
                setError(QStringLiteral("Switch clustered mode only when no targets are listed. Remove them, then switch."));
                return false;
            }
            iscsi.clustered = clustered;
        }
        if (form.sawPortals) {
            QVector<IscsiPortal> portals;
            for (const auto &line : form.portals) {
                const auto address = line.section(' ', 0, 0);
                const auto port = line.section(' ', 1, 1);
                static const QRegularExpression portOk("^[0-9]{1,5}$");
                if (address == "*" || !nfsHostOk(address) || !portOk.match(port).hasMatch()) {
                    setError(QStringLiteral("A portal looks like 0.0.0.0 3260."));
                    return false;
                }
                portals.append({address, port});
            }
            if (portals.isEmpty()) {
                setError(QStringLiteral("A target needs a portal."));
                return false;
            }
            target.portals = portals;
        }
        if (form.sawInitiators) {
            QVector<IscsiAcl> acls;
            for (const auto &line : form.initiators) {
                const auto parts = line.split(' ', Qt::SkipEmptyParts);
                if (parts.isEmpty() || parts.size() > 3 || !tokenOk(parts.at(0))) {
                    setError(QStringLiteral("An initiator line is the IQN, then an optional CHAP user and password."));
                    return false;
                }
                IscsiAcl acl;
                acl.initiator = parts.at(0);
                if (parts.size() > 1)
                    acl.userid = parts.at(1);
                if (parts.size() > 2)
                    acl.password = parts.at(2);
                if ((!acl.userid.isEmpty() && !tokenOk(acl.userid)) || (!acl.password.isEmpty() && !tokenOk(acl.password))) {
                    setError(QStringLiteral("CHAP uses letters and numbers so it can be sent without a shell."));
                    return false;
                }
                acls.append(acl);
            }
            target.acls = acls;
        }
    }
    pushUndo();
    m_samba = samba;
    m_nfs = nfs;
    m_iscsi = iscsi;
    setDirty(true);
    setError({});
    touch();
    return true;
}

QString Backend::globalText() const {
    QString text;
    text += "workgroup=" + m_samba.global.workgroup + "\n";
    text += "server string=" + m_samba.global.serverString + "\n";
    text += "log level=" + m_samba.global.logLevel + "\n";
    text += "macos=" + yesNo(m_samba.global.macos) + "\n";
    text += "advanced:\n";
    for (auto it = m_samba.global.extra.cbegin(); it != m_samba.global.extra.cend(); ++it)
        text += it.key() + " = " + it.value() + "\n";
    return text;
}

bool Backend::applyGlobal(const QString &text) {
    const auto form = parseEditor(text);
    auto global = m_samba.global;
    if (form.pairs.contains("workgroup")) {
        static const QRegularExpression workgroup("^[A-Za-z0-9_-]{1,15}$");
        if (!workgroup.match(form.pairs.value("workgroup")).hasMatch()) {
            setError(QStringLiteral("A workgroup is at most 15 letters or numbers."));
            return false;
        }
        global.workgroup = form.pairs.value("workgroup");
    }
    if (form.pairs.contains("server string")) {
        if (form.pairs.value("server string").contains(']')) {
            setError(QStringLiteral("The server string cannot contain ]."));
            return false;
        }
        global.serverString = form.pairs.value("server string");
    }
    if (form.pairs.contains("log level")) {
        static const QRegularExpression level("^[0-9A-Za-z: ]{1,40}$");
        if (!level.match(form.pairs.value("log level")).hasMatch()) {
            setError(QStringLiteral("Log level looks like 0 or 1 auth:3."));
            return false;
        }
        global.logLevel = form.pairs.value("log level");
    }
    if (form.pairs.contains("macos"))
        global.macos = asBool(form.pairs.value("macos"));
    QString error;
    if (!fillAdvanced(form.advanced, &global.extra, &error)) {
        setError(error);
        return false;
    }
    pushUndo();
    m_samba.global = global;
    setDirty(true);
    setError({});
    touch();
    return true;
}

QString Backend::exportText() const {
    if (m_protocol == 1)
        return nfsText(m_nfs);
    if (m_protocol == 2)
        return QString::fromUtf8(iscsiJson(m_iscsi));
    if (m_protocol == 3)
        return QString("{\n    \"rustfs\": \"%1\"\n}\n").arg(m_library.rustfsEndpoint);
    return sambaShareText(m_samba.global, m_samba.shares);
}

bool Backend::importText(const QString &text) {
    if (m_protocol == 3) {
        const auto url = QJsonDocument::fromJson(text.toUtf8()).object().value("rustfs").toString();
        if (!loopbackOrigin(url)) {
            setError(QStringLiteral("RustFS has to be http://127.0.0.1 and a port."));
            return false;
        }
        pushUndo();
        m_library.rustfsEndpoint = url;
        setDirty(true);
        setError({});
        touch();
        return true;
    }
    if (m_protocol == 0) {
        auto parsed = parseSamba(text);
        static const QRegularExpression global("^\\s*\\[global\\]", QRegularExpression::CaseInsensitiveOption | QRegularExpression::MultilineOption);
        if (!global.match(text).hasMatch())
            parsed.global = m_samba.global;
        for (const auto &share : parsed.shares) {
            if (!shareNameOk(share.name) || !absolutePathOk(share.path)) {
                setError(QStringLiteral("A share in that file has a name or path Shares will not write."));
                return false;
            }
        }
        pushUndo();
        m_samba = parsed;
    } else if (m_protocol == 1) {
        const auto parsed = parseNfs(text);
        if (parsed.isEmpty() && !text.trimmed().isEmpty()) {
            setError(QStringLiteral("Nothing in that export file could be read."));
            return false;
        }
        for (const auto &exp : parsed) {
            if (!absolutePathOk(exp.path)) {
                setError(QStringLiteral("An export path has to be an absolute path."));
                return false;
            }
        }
        pushUndo();
        m_nfs = parsed;
    } else {
        bool ok = false;
        const auto parsed = parseIscsiJson(text.toUtf8(), &ok);
        if (!ok) {
            setError(QStringLiteral("That iSCSI file could not be read."));
            return false;
        }
        pushUndo();
        m_iscsi = parsed;
    }
    const int counts[] = {int(m_samba.shares.size()), int(m_nfs.size()), int(m_iscsi.targets.size())};
    m_ids[m_protocol].clear();
    for (int i = 0; i < counts[m_protocol]; ++i)
        m_ids[m_protocol].append(m_nextId++);
    m_selected[m_protocol] = m_ids[m_protocol].isEmpty() ? -1 : m_ids[m_protocol].first();
    setDirty(true);
    setError({});
    touch();
    return true;
}

bool Backend::knownBackend(const QString &backend) const {
    return backend == "minio" || backend == "garage" || backend == "ceph" || backend == "rustfs";
}

bool Backend::setSambaPassword(const QString &user, const QString &password) {
    const auto name = user.trimmed();
    if (!accountNameOk(name)) {
        setError(QStringLiteral("Account names are lowercase and start with a letter."));
        return false;
    }
    if (password.isEmpty() || password.contains('\n') || password.contains('\r')) {
        setError(QStringLiteral("The Samba password cannot be empty or contain a line break."));
        return false;
    }
    Plan plan;
    // smbpasswd reads the password twice on stdin. It is not a command argument,
    // and the Linux login password is left alone.
    plan.commands.append({{"smbpasswd", "-s", "-a", name}, password + "\n" + password + "\n"});
    if (!runPlan(plan))
        return false;
    bool found = false;
    for (auto &account : m_users) {
        if (account.name == name) {
            account.samba = true;
            found = true;
        }
    }
    if (!found)
        m_users.append({name, true});
    m_lastOutput.clear();
    touch();
    return true;
}

bool Backend::removeSambaPassword(const QString &user) {
    const auto name = user.trimmed();
    if (!accountNameOk(name)) {
        setError(QStringLiteral("Account names are lowercase and start with a letter."));
        return false;
    }
    Plan plan;
    plan.commands.append({{"smbpasswd", "-x", name}, {}});
    if (!runPlan(plan))
        return false;
    for (auto &account : m_users) {
        if (account.name == name)
            account.samba = false;
    }
    touch();
    return true;
}

bool Backend::createAccess(const QString &backend, const QString &name, const QString &secret) {
    const auto which = backend.trimmed();
    if (!m_s3Backends.contains(which)) {
        setError(which.isEmpty() ? QStringLiteral("Name the backend.") : which + " is not installed.");
        return false;
    }
    QString error;
    const auto args = s3AccessArgs(which, "create", name.trimmed(), secret, &error);
    if (args.isEmpty()) {
        setError(error);
        return false;
    }
    Plan plan;
    plan.commands.append({args, {}});
    QString output;
    if (!runPlan(plan, &output))
        return false;
    m_lastOutput = output.left(4000);
    m_s3.access.append({which, name.trimmed(), which == "garage" ? QStringLiteral("key") : QStringLiteral("user")});
    touch();
    return true;
}

bool Backend::removeAccess(const QString &backend, const QString &name) {
    const auto which = backend.trimmed();
    const auto account = name.trimmed();
    if (!m_s3Backends.contains(which)) {
        setError(which.isEmpty() ? QStringLiteral("Name the backend.") : which + " is not installed.");
        return false;
    }
    QString error;
    const auto args = s3AccessArgs(which, "delete", account, {}, &error);
    if (args.isEmpty()) {
        setError(error);
        return false;
    }
    Plan plan;
    plan.commands.append({args, {}});
    if (!runPlan(plan))
        return false;
    for (int i = m_s3.access.size() - 1; i >= 0; --i) {
        if (m_s3.access.at(i).backend == which && m_s3.access.at(i).name == account)
            m_s3.access.removeAt(i);
    }
    touch();
    return true;
}

bool Backend::runPlan(const Plan &plan, QString *output) {
    if (!plan.error.isEmpty()) {
        setError(plan.error);
        return false;
    }
    QString error;
    const bool ok = m_root == "/" ? commitWithPkexec(plan, &error, output) : applyPlan(m_root, plan, m_commands, &error, output);
    if (!ok)
        setError(error.isEmpty() ? QStringLiteral("The change was not applied.") : error);
    else
        setError({});
    return ok;
}

bool Backend::commitWithPkexec(const Plan &plan, QString *error, QString *output) {
    if (QStandardPaths::findExecutable(QStringLiteral("pkexec")).isEmpty()) {
        if (error)
            *error = QStringLiteral("pkexec is not installed");
        return false;
    }
    QProcess process;
    process.start(QStringLiteral("pkexec"), {QCoreApplication::applicationFilePath(), QStringLiteral("--privileged")});
    if (!process.waitForStarted(5000)) {
        if (error)
            *error = QStringLiteral("Could not start pkexec. ") + process.errorString();
        return false;
    }
    process.write(planToJson(plan));
    process.closeWriteChannel();
    // The polkit dialog is a separate process. This window waits for it.
    if (!process.waitForFinished(120000)) {
        process.kill();
        process.waitForFinished(1000);
        if (error)
            *error = QStringLiteral("The authorization dialog timed out.");
        return false;
    }
    if (output)
        output->append(QString::fromUtf8(process.readAllStandardOutput()));
    if (process.exitCode() != 0) {
        const auto err = QString::fromUtf8(process.readAllStandardError()).trimmed();
        if (error)
            *error = err.isEmpty() ? QStringLiteral("The change was not applied.") : err;
        return false;
    }
    return true;
}

void Backend::touch() { emit modelChanged(); }

void Backend::setDirty(bool dirty) {
    if (m_dirty == dirty)
        return;
    m_dirty = dirty;
    emit dirtyChanged();
}

void Backend::setError(const QString &error) {
    if (m_error == error)
        return;
    m_error = error;
    emit errorChanged();
}
