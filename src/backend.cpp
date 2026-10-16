#include "backend.h"

#include "portalfilepicker.h"
#include "remote.h"

#include <algorithm>

#include <QClipboard>
#include <QCoreApplication>
#include <QDate>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QGuiApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPointer>
#include <QSaveFile>
#include <QProcess>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QTemporaryFile>
#include <QThreadPool>
#include <QDeadlineTimer>
#include <QUrl>

#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <utility>

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

bool smbHostOk(const QString &host) {
    static const QRegularExpression re("^[A-Za-z0-9][A-Za-z0-9.-]{0,253}$");
    return re.match(host).hasMatch() && !host.contains("..") && !host.endsWith('.');
}

} // namespace

bool windowsAdminShare(const QString &name) {
    const auto upper = name.toUpper();
    if (upper == QLatin1String("IPC$") || upper == QLatin1String("ADMIN$") || upper == QLatin1String("PRINT$") ||
        upper == QLatin1String("FAX$"))
        return true;
    // Windows publishes each drive as C$, D$, and so on. A longer name such as
    // zfsback1$ is a real share that happens to use the same character.
    return upper.size() == 2 && upper.at(0).isLetter() && upper.at(1) == QLatin1Char('$');
}

QVariantList parseSmbGrepableList(const QString &output) {
    QVariantList shares;
    for (const auto &line : output.split('\n')) {
        const auto fields = line.trimmed().split('|');
        if (fields.size() < 2 || fields.at(0).compare(QStringLiteral("Disk"), Qt::CaseInsensitive) != 0)
            continue;
        const auto name = fields.at(1).trimmed();
        if (name.isEmpty() || windowsAdminShare(name))
            continue;
        shares.append(QVariantMap{{QStringLiteral("name"), name},
                                  {QStringLiteral("comment"), fields.size() > 2 ? fields.mid(2).join('|').trimmed() : QString()}});
    }
    return shares;
}

QStringList lanIpv4Hosts(const QString &address, int prefix, QString *error) {
    const auto reject = [error](const QString &message) {
        if (error)
            *error = message;
        return QStringList{};
    };
    const auto parts = address.split('.');
    if (parts.size() != 4 || prefix < 0 || prefix > 32)
        return reject(QStringLiteral("The network address is not usable."));
    quint32 ip = 0;
    for (const auto &part : parts) {
        bool ok = false;
        const int octet = part.toInt(&ok);
        if (!ok || octet < 0 || octet > 255)
            return reject(QStringLiteral("The network address is not usable."));
        ip = (ip << 8) | quint32(octet);
    }
    const quint32 high = (ip >> 24) & 0xff;
    const quint32 next = (ip >> 16) & 0xff;
    const bool privateLan = high == 10 || (high == 192 && next == 168) || (high == 172 && next >= 16 && next <= 31);
    if (!privateLan)
        return reject(QStringLiteral("Shares only scans a private local network."));
    if (prefix < 22)
        return reject(QStringLiteral("That network is too large to scan."));
    if (prefix > 30)
        return reject(QStringLiteral("That network has no other computers to scan."));

    const quint32 count = 1u << (32 - prefix);
    const quint32 network = ip & (0xffffffffu << (32 - prefix));
    QStringList hosts;
    hosts.reserve(int(count) - 2);
    for (quint32 host = 1; host + 1 < count; ++host) {
        const quint32 addressBits = network + host;
        hosts.append(QStringLiteral("%1.%2.%3.%4")
                         .arg((addressBits >> 24) & 255)
                         .arg((addressBits >> 16) & 255)
                         .arg((addressBits >> 8) & 255)
                         .arg(addressBits & 255));
    }
    if (error)
        error->clear();
    return hosts;
}

namespace {

struct SmbScanResult {
    QVariantList shares;
    QString error;
};

QString smbCredentialError(const QString &user, const QString &password) {
    if (user.contains(u'\n') || user.contains(u'\r') || password.contains(u'\n') || password.contains(u'\r'))
        return QStringLiteral("The SMB username and password cannot contain line breaks.");
    if (user.isEmpty() && !password.isEmpty())
        return QStringLiteral("Enter a username with the password, or leave both fields empty for guest access.");
    return {};
}

int ipv4Prefix(quint32 mask) {
    int bits = 0;
    bool seenZero = false;
    for (int bit = 31; bit >= 0; --bit) {
        if (mask & (1u << bit)) {
            if (seenZero)
                return -1;
            ++bits;
        } else {
            seenZero = true;
        }
    }
    return bits;
}

QString ipv4Text(quint32 address) {
    return QStringLiteral("%1.%2.%3.%4")
        .arg((address >> 24) & 255)
        .arg((address >> 16) & 255)
        .arg((address >> 8) & 255)
        .arg(address & 255);
}

quint32 ipv4Value(const QString &text) {
    quint32 value = 0;
    const auto parts = text.split('.');
    if (parts.size() != 4)
        return 0;
    for (const auto &part : parts) {
        bool ok = false;
        const int octet = part.toInt(&ok);
        if (!ok || octet < 0 || octet > 255)
            return 0;
        value = (value << 8) | quint32(octet);
    }
    return value;
}

QStringList planLanHosts(QString *error) {
    QStringList hosts;
    bool sawPrivate = false;
    bool tooLarge = false;
    ifaddrs *list = nullptr;
    if (getifaddrs(&list) != 0) {
        if (error)
            *error = QStringLiteral("Could not read this computer's network addresses.");
        return {};
    }
    for (auto *ifa = list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || !ifa->ifa_netmask || ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK))
            continue;
        const auto address = ntohl(reinterpret_cast<sockaddr_in *>(ifa->ifa_addr)->sin_addr.s_addr);
        const auto mask = ntohl(reinterpret_cast<sockaddr_in *>(ifa->ifa_netmask)->sin_addr.s_addr);
        const int prefix = ipv4Prefix(mask);
        if (prefix < 0)
            continue;
        QString oneError;
        const auto found = lanIpv4Hosts(ipv4Text(address), prefix, &oneError);
        if (oneError.contains(QStringLiteral("private")))
            continue;
        sawPrivate = true;
        if (found.isEmpty()) {
            if (oneError.contains(QStringLiteral("too large")))
                tooLarge = true;
            continue;
        }
        for (const auto &host : found) {
            if (!hosts.contains(host))
                hosts.append(host);
        }
    }
    freeifaddrs(list);
    std::sort(hosts.begin(), hosts.end(), [](const QString &left, const QString &right) {
        return ipv4Value(left) < ipv4Value(right);
    });
    if (hosts.isEmpty() && error) {
        if (tooLarge)
            *error = QStringLiteral("The local network is too large to scan.");
        else if (sawPrivate)
            *error = QStringLiteral("That network has no other computers to scan.");
        else
            *error = QStringLiteral("This computer is not on a private local network Shares can scan.");
    } else if (error) {
        error->clear();
    }
    return hosts;
}

QStringList hostsWithSmb(const QStringList &hosts) {
    QStringList open;
    constexpr int batch = 64;
    constexpr int timeoutMs = 250;
    for (int start = 0; start < hosts.size(); start += batch) {
        const int count = qMin(batch, hosts.size() - start);
        QVector<int> fds(count, -1);
        QStringList batchHosts;
        for (int i = 0; i < count; ++i) {
            const auto host = hosts.at(start + i);
            batchHosts.append(host);
            const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (fd < 0)
                continue;
            const int flags = ::fcntl(fd, F_GETFL, 0);
            if (flags >= 0)
                ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_port = htons(445);
            address.sin_addr.s_addr = htonl(ipv4Value(host));
            const int rc = ::connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address));
            if (rc == 0) {
                open.append(host);
                ::close(fd);
                continue;
            }
            if (errno != EINPROGRESS) {
                ::close(fd);
                continue;
            }
            fds[i] = fd;
        }
        QDeadlineTimer deadline(timeoutMs);
        while (!deadline.hasExpired()) {
            QVector<pollfd> pfds;
            QVector<int> index;
            for (int i = 0; i < fds.size(); ++i) {
                if (fds.at(i) < 0)
                    continue;
                pollfd pfd{};
                pfd.fd = fds.at(i);
                pfd.events = POLLOUT;
                pfds.append(pfd);
                index.append(i);
            }
            if (pfds.isEmpty())
                break;
            const int wait = int(qBound(qint64(0), deadline.remainingTime(), qint64(timeoutMs)));
            const int ready = ::poll(pfds.data(), nfds_t(pfds.size()), wait);
            if (ready == 0)
                break;
            for (int k = 0; k < pfds.size(); ++k) {
                if (!(pfds.at(k).revents & (POLLOUT | POLLERR | POLLHUP)))
                    continue;
                int soerr = 0;
                socklen_t len = sizeof(soerr);
                ::getsockopt(pfds.at(k).fd, SOL_SOCKET, SO_ERROR, &soerr, &len);
                if (soerr == 0 && (pfds.at(k).revents & POLLOUT))
                    open.append(batchHosts.at(index.at(k)));
                ::close(pfds.at(k).fd);
                fds[index.at(k)] = -1;
            }
        }
        for (int fd : fds) {
            if (fd >= 0)
                ::close(fd);
        }
    }
    return open;
}

SmbScanResult scanSmbShares(const QString &host, const QString &user, const QString &password, int timeoutMs = 20000) {
    SmbScanResult result;
    const auto smbclient = QStandardPaths::findExecutable(QStringLiteral("smbclient"));
    if (smbclient.isEmpty()) {
        result.error = QStringLiteral("smbclient is not installed on this computer. Install the smbclient package.");
        return result;
    }

    // A private config keeps a broken local smb.conf from hiding the server's shares.
    QTemporaryFile config;
    if (!config.open()) {
        result.error = QStringLiteral("Could not prepare the SMB client settings.");
        return result;
    }
    config.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    const auto settings = QStringLiteral("[global]\nclient min protocol = SMB2\nclient max protocol = SMB3\n").toUtf8();
    if (config.write(settings) != settings.size() || !config.flush()) {
        result.error = QStringLiteral("Could not prepare the SMB client settings.");
        return result;
    }
    QStringList args{QStringLiteral("-s"), config.fileName(), QStringLiteral("-g"), QStringLiteral("-L"), host};
    QTemporaryFile auth;
    if (!user.isEmpty() || !password.isEmpty()) {
        if (!auth.open()) {
            result.error = QStringLiteral("Could not prepare private SMB credentials.");
            return result;
        }
        auth.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
        const auto credentials = QStringLiteral("username = %1\npassword = %2\n").arg(user, password).toUtf8();
        if (auth.write(credentials) != credentials.size() || !auth.flush()) {
            result.error = QStringLiteral("Could not prepare private SMB credentials.");
            return result;
        }
        args << QStringLiteral("-A") << auth.fileName();
        auth.close();
    } else {
        args << QStringLiteral("-N");
    }

    QProcess process;
    process.start(smbclient, args);
    if (!process.waitForStarted(5000)) {
        result.error = QStringLiteral("Could not start smbclient: ") + process.errorString();
        return result;
    }
    if (!process.waitForFinished(timeoutMs)) {
        process.kill();
        process.waitForFinished(1000);
        result.error = QStringLiteral("Searching SMB shares timed out.");
        return result;
    }

    const auto output = QString::fromUtf8(process.readAllStandardOutput());
    const auto stderrText = QString::fromUtf8(process.readAllStandardError()).trimmed();
    result.shares = parseSmbGrepableList(output);
    if (process.exitCode() != 0 && result.shares.isEmpty())
        result.error = stderrText.isEmpty() ? QStringLiteral("Could not list shares on %1.").arg(host) : stderrText;
    else if (result.shares.isEmpty())
        result.error = QStringLiteral("No visible SMB shares were found on %1.").arg(host);
    return result;
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

QString startFolder(const QString &currentPath) {
    if (currentPath.startsWith('/')) {
        const QFileInfo info(currentPath);
        if (info.isDir())
            return info.absoluteFilePath();
        if (info.dir().exists())
            return info.dir().absolutePath();
    }
    return QDir::homePath();
}

QString imageName(const QString &currentPath, const QString &currentName) {
    const QFileInfo info(currentPath);
    if (currentPath.startsWith('/') && !info.isDir() && !info.fileName().isEmpty())
        return info.fileName();
    const auto name = currentName.trimmed();
    if (shareNameOk(name))
        return name.endsWith(QStringLiteral(".img")) ? name : name + QStringLiteral(".img");
    return QStringLiteral("disk.img");
}

// OpenSSH joins the remote command and a shell parses it. One pair of single
// quotes keeps spaces and $() inside a path from becoming more arguments.
QString quoteShell(const QString &text) {
    QString quoted = QStringLiteral("'");
    for (const auto &ch : text) {
        if (ch == u'\'')
            quoted += QStringLiteral("'\\''");
        else
            quoted += ch;
    }
    quoted += u'\'';
    return quoted;
}

bool folderNameOk(const QString &name) {
    return !name.isEmpty() && name != QStringLiteral(".") && name != QStringLiteral("..") && !name.contains('/')
        && !name.contains('\n') && !name.contains('\r');
}

QString parentPath(const QString &path) {
    if (path == QStringLiteral("/"))
        return path;
    const auto slash = path.lastIndexOf('/');
    return slash > 0 ? path.left(slash) : QStringLiteral("/");
}

} // namespace

Backend::Backend(const QString &root, Commands *commands, FilePicker *picker, RemoteLink *link, QObject *parent)
    : QObject(parent), m_owned(commands ? nullptr : std::make_shared<Commands>()),
      m_localCommands(commands ? commands : m_owned.get()), m_commands(m_localCommands), m_link(link),
      m_injectedLink(link), m_deferProbes(commands == nullptr), m_appRoot(cleanRoot(root)), m_root(m_appRoot),
      m_library(m_root, m_commands), m_picker(picker) {
    if (m_picker)
        connectPicker();
    if (m_appRoot == "/") {
        QFile release("/etc/os-release");
        QString id;
        QString like;
        if (release.open(QIODevice::ReadOnly)) {
            const auto text = QString::fromUtf8(release.readAll());
            for (const auto &line : text.split('\n')) {
                if (line.startsWith("ID="))
                    id = line.mid(3).trimmed().remove('"');
                if (line.startsWith("ID_LIKE="))
                    like = line.mid(8).trimmed().remove('"');
            }
        }
        m_localProfile = profileForRelease(id, like);
    }
    m_library.setProfile(m_localProfile);
    loadSavedHosts();
    reload();
}

void Backend::reload() {
    const int wave = ++m_wave;
    ++m_s3Wave;
    m_s3Ready = false;
    m_sessionsReady[0] = m_sessionsReady[1] = m_sessionsReady[2] = false;
    if (m_mirror && m_link && m_deferProbes) {
        scheduleRemoteReload(wave);
        return;
    }
    QString pullError;
    if (m_mirror && m_link) {
        if (!pullRemoteFiles(m_link, m_mirror->path(), &pullError)) {
            // Keep going with whatever was copied so the window still opens.
        }
        m_library.setRoot(m_mirror->path());
        m_root = m_mirror->path();
    }
    finishReload(wave, pullError);
}

void Backend::finishReload(int wave, const QString &pullError) {
    if (wave != m_wave)
        return;
    // Config files are local and small. Publish them before the process probes
    // so the window is up while systemctl, tailscale, and SSH are still running.
    m_library.loadFiles();
    if (m_deferProbes) {
        m_library.sambaState = QStringLiteral("checking");
        m_library.nfsState = QStringLiteral("checking");
        m_library.iscsiState = QStringLiteral("checking");
        m_library.s3State = QStringLiteral("checking");
        m_library.reachable.clear();
        m_library.users.clear();
        m_library.tailscaleStatus.clear();
    } else {
        m_library.loadStatus();
    }
    copyFromLibrary();
    m_filter.clear();
    m_undo.clear();
    m_redo.clear();
    setError(pullError);
    emit protocolChanged();
    emit dirtyChanged();
    emit historyChanged();
    touch();
    if (m_protocol == 3)
        ensureS3();
    else
        ensureSessions(m_protocol);
    if (m_deferProbes)
        scheduleStatus(wave);
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
    m_peers = tailscalePeers(m_library.tailscaleStatus);
    publishHosts();
}

std::shared_ptr<Commands> Backend::liveCommands() const {
    if (m_remoteCommands)
        return m_remoteCommands;
    return m_owned;
}

void Backend::scheduleStatus(int wave) {
    auto commands = liveCommands();
    if (!commands)
        return;
    const auto profile = m_library.profile();
    const bool clustered = m_library.iscsi.clustered;
    QPointer<Backend> self(this);
    QThreadPool::globalInstance()->start([commands, profile, clustered, wave, self] {
        Library library(QStringLiteral("/"), commands.get());
        library.setProfile(profile);
        library.iscsi.clustered = clustered;
        library.loadStatus();
        LiveStatus status;
        status.wave = wave;
        status.sambaState = library.sambaState;
        status.nfsState = library.nfsState;
        status.iscsiState = library.iscsiState;
        status.reachable = library.reachable;
        status.tailscaleStatus = library.tailscaleStatus;
        status.users = library.users;
        auto *app = QCoreApplication::instance();
        if (!app)
            return;
        QMetaObject::invokeMethod(app, [self, status] {
            if (!self || status.wave != self->m_wave)
                return;
            self->applyLiveStatus(status);
        }, Qt::QueuedConnection);
    });
}

void Backend::applyLiveStatus(const LiveStatus &status) {
    m_library.sambaState = status.sambaState;
    m_library.nfsState = status.nfsState;
    m_library.iscsiState = status.iscsiState;
    m_library.reachable = status.reachable;
    m_library.tailscaleStatus = status.tailscaleStatus;
    m_library.users = status.users;
    m_sambaState = status.sambaState;
    m_nfsState = status.nfsState;
    m_iscsiState = status.iscsiState;
    m_reachable = status.reachable;
    m_users = status.users;
    m_peers = tailscalePeers(status.tailscaleStatus);
    publishHosts();
    touch();
}

void Backend::ensureSessions(int protocol) {
    if (protocol < 0 || protocol > 2 || m_sessionsReady[protocol])
        return;
    if (!m_deferProbes) {
        m_library.loadSessions(protocol);
        m_sambaSessions = m_library.sambaSessions;
        m_nfsSessions = m_library.nfsSessions;
        m_iscsiSessions = m_library.iscsiSessions;
        m_sessionsReady[protocol] = true;
        touch();
        return;
    }
    auto commands = liveCommands();
    if (!commands)
        return;
    const int wave = m_wave;
    QPointer<Backend> self(this);
    QThreadPool::globalInstance()->start([commands, protocol, wave, self] {
        Library library(QStringLiteral("/"), commands.get());
        library.loadSessions(protocol);
        QStringList sessions = protocol == 0 ? library.sambaSessions : protocol == 1 ? library.nfsSessions : library.iscsiSessions;
        auto *app = QCoreApplication::instance();
        if (!app)
            return;
        QMetaObject::invokeMethod(app, [self, wave, protocol, sessions] {
            if (!self)
                return;
            self->applySessions(wave, protocol, sessions);
        }, Qt::QueuedConnection);
    });
}

void Backend::applySessions(int wave, int protocol, const QStringList &sessions) {
    if (wave != m_wave || protocol < 0 || protocol > 2)
        return;
    if (protocol == 0)
        m_sambaSessions = sessions;
    else if (protocol == 1)
        m_nfsSessions = sessions;
    else
        m_iscsiSessions = sessions;
    m_sessionsReady[protocol] = true;
    touch();
}

void Backend::ensureS3() {
    if (m_s3Ready)
        return;
    if (m_deferProbes) {
        if (m_s3State != QStringLiteral("checking")) {
            m_s3State = QStringLiteral("checking");
            touch();
        }
        scheduleS3(m_s3Wave);
        return;
    }
    m_library.loadS3();
    adoptS3();
}

void Backend::refreshS3() {
    m_s3Ready = false;
    ++m_s3Wave;
    ensureS3();
}

void Backend::scheduleS3(int wave) {
    auto commands = liveCommands();
    if (!commands)
        return;
    const auto root = m_root;
    const auto endpoint = m_library.rustfsEndpoint;
    const auto profile = m_library.profile();
    QPointer<Backend> self(this);
    QThreadPool::globalInstance()->start([commands, root, endpoint, profile, wave, self] {
        Library library(root, commands.get());
        library.setProfile(profile);
        library.rustfsEndpoint = endpoint;
        library.loadS3();
        S3Status status;
        status.wave = wave;
        status.state = library.s3State;
        status.backends = library.s3Backends;
        status.config = library.s3;
        status.notice = library.notice;
        auto *app = QCoreApplication::instance();
        if (!app)
            return;
        QMetaObject::invokeMethod(app, [self, status] {
            if (!self)
                return;
            self->applyS3(status);
        }, Qt::QueuedConnection);
    });
}

void Backend::applyS3(const S3Status &status) {
    if (status.wave != m_s3Wave)
        return;
    m_library.s3 = status.config;
    m_library.s3Backends = status.backends;
    m_library.s3State = status.state;
    if (!status.notice.isEmpty() && !m_library.notice.contains(status.notice))
        m_library.notice += (m_library.notice.isEmpty() ? QString() : QStringLiteral(" ")) + status.notice;
    adoptS3();
}

void Backend::adoptS3() {
    m_s3 = m_library.s3;
    m_s3Backends = m_library.s3Backends;
    m_s3State = m_library.s3State;
    m_notice = m_library.notice;
    m_ids[3].clear();
    for (int i = 0; i < m_s3.buckets.size(); ++i)
        m_ids[3].append(m_nextId++);
    m_selected[3] = m_ids[3].isEmpty() ? -1 : m_ids[3].first();
    m_s3Ready = true;
    touch();
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
        return QStringLiteral("The folder browser opens so you can pick or create the export. Arrows and the mouse both move through it. Change the clients with Edit, then Save.");
    case 2:
        return QStringLiteral("The file browser opens so you can place the disk image. Create Folder makes its directory. Save creates the image. Removing the target leaves that image in place.");
    case 3:
        return QStringLiteral("Creates the bucket on the named backend now. Ceph buckets are created through the S3 API, not here.");
    default:
        return QStringLiteral("The folder browser opens so you can pick or create the folder. Arrows and the mouse both move through it. The name stays fixed after this. Save writes it.");
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
    if (protocol == 3)
        ensureS3();
    else
        ensureSessions(protocol);
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

void Backend::setBrowsing(bool browsing) {
    if (m_browsing == browsing)
        return;
    m_browsing = browsing;
    emit browsingChanged();
}

void Backend::connectPicker() {
    connect(m_picker, &FilePicker::chosen, this, &Backend::acceptPickedPath);
    connect(m_picker, &FilePicker::cancelled, this, [this] { setBrowsing(false); });
    connect(m_picker, &FilePicker::failed, this, [this](const QString &message) {
        setBrowsing(false);
        setError(message);
    });
}

void Backend::acceptPickedPath(const QString &path) {
    setBrowsing(false);
    if (!absolutePathOk(path)) {
        setError(m_protocol == 2 ? QStringLiteral("The disk image path has to be an absolute path.")
                 : m_protocol == 1 ? QStringLiteral("An export needs an absolute folder.")
                                   : QStringLiteral("A share path has to be an absolute path."));
        return;
    }
    setError({});
    emit createPathChosen(path);
}

QString Backend::childPath(const QString &dir, const QString &name) {
    if (dir == QStringLiteral("/"))
        return QStringLiteral("/") + name;
    return dir + QStringLiteral("/") + name;
}

bool Backend::openRemoteBrowse(const QString &path) {
    if (!m_link || !absolutePathOk(path)) {
        setError(QStringLiteral("That folder is not on this computer."));
        return false;
    }
    const auto quoted = quoteShell(path);
    const auto check = m_link->exec({QStringLiteral("test"), QStringLiteral("-d"), quoted}, {}, 8000);
    if (check.code != 0) {
        const auto message = check.err.trimmed();
        setError(message.isEmpty() ? QStringLiteral("That folder is not on this computer.") : message);
        return false;
    }
    const auto listed = m_link->exec({QStringLiteral("ls"), QStringLiteral("-1"), QStringLiteral("-A"), QStringLiteral("-p"),
                                      QStringLiteral("--color=never"), QStringLiteral("--quoting-style=literal"),
                                      QStringLiteral("--"), quoted},
                                     {}, 20000);
    if (listed.code != 0) {
        const auto message = listed.err.trimmed().isEmpty() ? listed.out.trimmed() : listed.err.trimmed();
        setError(message.isEmpty() ? QStringLiteral("That folder could not be listed.") : message);
        return false;
    }
    struct Row {
        QString name;
        bool dir = false;
    };
    QVector<Row> rows;
    for (auto line : listed.out.split('\n')) {
        line = line.trimmed();
        if (line.isEmpty())
            continue;
        const bool dir = line.endsWith('/');
        if (dir)
            line.chop(1);
        if (line.isEmpty() || line == QStringLiteral(".") || line == QStringLiteral("..") || line.contains('/'))
            continue;
        rows.append({line, dir});
    }
    std::sort(rows.begin(), rows.end(), [](const Row &a, const Row &b) {
        if (a.dir != b.dir)
            return a.dir;
        return a.name.localeAwareCompare(b.name) < 0;
    });
    m_browseRows.clear();
    for (const auto &row : rows)
        m_browseRows.append(QVariantMap{{"name", row.name}, {"dir", row.dir}});
    m_browsePath = path;
    setError({});
    emit browseChanged();
    return true;
}

bool Backend::beginRemoteBrowse(const QString &path) {
    if (openRemoteBrowse(path))
        return true;
    const auto parent = parentPath(path);
    if (parent != path && openRemoteBrowse(parent))
        return true;
    if (parent != QStringLiteral("/") && openRemoteBrowse(QStringLiteral("/")))
        return true;
    return false;
}

void Backend::browseForCreate(const QString &currentPath, const QString &currentName) {
    if (m_browsing)
        return;
    if (m_protocol == 3) {
        setError(QStringLiteral("S3 buckets have no folder. Name the backend instead."));
        return;
    }
    if (remote()) {
        m_browseFile = m_protocol == 2 ? imageName(currentPath, currentName) : QString();
        QString path = QStringLiteral("/");
        if (absolutePathOk(currentPath))
            path = m_protocol == 2 ? parentPath(currentPath) : currentPath;
        if (!beginRemoteBrowse(path))
            return;
        setBrowsing(true);
        emit browseChanged();
        return;
    }
    if (!m_picker) {
        m_ownedPicker = std::make_unique<PortalFilePicker>();
        m_picker = m_ownedPicker.get();
        connectPicker();
    }
    setBrowsing(true);
    const auto folder = startFolder(currentPath);
    if (m_protocol == 2)
        m_picker->chooseNewFile(QStringLiteral("Disk image"), folder, imageName(currentPath, currentName));
    else
        m_picker->chooseFolder(m_protocol == 1 ? QStringLiteral("Folder to export") : QStringLiteral("Folder to share"),
                               folder);
}

void Backend::browseEnter(int index) {
    if (!m_browsing || !remote() || index < 0 || index >= m_browseRows.size())
        return;
    const auto row = m_browseRows.at(index).toMap();
    const auto path = childPath(m_browsePath, row.value("name").toString());
    if (row.value("dir").toBool()) {
        openRemoteBrowse(path);
        return;
    }
    if (m_protocol == 2) {
        acceptPickedPath(path);
        return;
    }
    setError(QStringLiteral("That is a file. Use this folder, or open a directory."));
}

void Backend::browseUp() {
    if (!m_browsing || !remote())
        return;
    openRemoteBrowse(parentPath(m_browsePath));
}

bool Backend::browseMake(const QString &name) {
    if (!m_browsing || !remote() || !m_link)
        return false;
    const auto folder = name.trimmed();
    if (!folderNameOk(folder)) {
        setError(QStringLiteral("A folder name cannot include / or be empty."));
        return false;
    }
    const auto path = childPath(m_browsePath, folder);
    if (!absolutePathOk(path)) {
        setError(QStringLiteral("A share path has to be an absolute path."));
        return false;
    }
    const auto made = m_link->exec({QStringLiteral("mkdir"), QStringLiteral("--"), quoteShell(path)}, {}, 20000);
    if (made.code != 0) {
        const auto message = made.err.trimmed().isEmpty() ? made.out.trimmed() : made.err.trimmed();
        setError(message.isEmpty() ? QStringLiteral("Could not create that folder.") : message);
        return false;
    }
    openRemoteBrowse(m_browsePath);
    return true;
}

void Backend::browseChoose(const QString &fileName) {
    if (!m_browsing || !remote())
        return;
    auto path = m_browsePath;
    if (m_protocol == 2) {
        const auto file = fileName.trimmed();
        if (!folderNameOk(file)) {
            setError(QStringLiteral("A disk image needs a file name."));
            return;
        }
        path = childPath(m_browsePath, file);
    }
    acceptPickedPath(path);
}

void Backend::browseCancel() { setBrowsing(false); }

bool Backend::create(const QString &name, const QString &path) {
    const auto trimmedName = name.trimmed();
    const auto trimmedPath = path.trimmed();
    if (m_protocol == 3) {
        if (m_deferProbes && !m_s3Ready) {
            setError(QStringLiteral("S3 is still loading."));
            return false;
        }
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
        refreshS3();
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
        refreshS3();
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
    refreshS3();
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
    refreshS3();
    return true;
}

bool Backend::runPlan(const Plan &plan, QString *output) {
    if (!plan.error.isEmpty()) {
        setError(plan.error);
        return false;
    }
    if (m_mirror && m_link) {
        QFile helper(QStringLiteral(":/shares_apply.py"));
        if (!helper.open(QIODevice::ReadOnly)) {
            setError(QStringLiteral("The apply helper is missing from the app."));
            return false;
        }
        QString error;
        if (!applyRemotePlan(m_link, helper.readAll(), planToJson(plan), &error, output)) {
            setError(error.isEmpty() ? QStringLiteral("The change was not applied.") : error);
            return false;
        }
        // Keep the local mirror in step with what the remote computer stored,
        // without running the remote commands a second time on this machine.
        applyPlan(m_mirror->path(), plan, nullptr, &error);
        setError({});
        return true;
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

QString Backend::localUser() const {
    const auto user = qEnvironmentVariable("USER");
    return accountNameOk(user) ? user : QStringLiteral("root");
}

QString Backend::hostsPath() const {
    if (!m_hostsFile.isEmpty())
        return m_hostsFile;
    if (m_appRoot != "/")
        return {};
    const auto dir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    return dir.isEmpty() ? QString() : dir + QStringLiteral("/hosts.json");
}

void Backend::setHostsFile(const QString &path) {
    m_hostsFile = path;
    loadSavedHosts();
    publishHosts();
}

void Backend::loadSavedHosts() {
    m_saved.clear();
    m_loginUsers.clear();
    m_loginPasswords.clear();
    const auto path = hostsPath();
    if (path.isEmpty())
        return;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return;
    const auto root = QJsonDocument::fromJson(file.readAll()).object();
    const auto list = root.value("hosts").toArray();
    for (const auto &value : list) {
        const auto obj = value.toObject();
        RemoteHost host;
        host.name = obj.value("name").toString();
        host.user = obj.value("user").toString();
        host.host = obj.value("host").toString();
        host.port = obj.value("port").toInt(22);
        host.via = obj.value("via").toString();
        host.tailscaleSsh = obj.value("tailscaleSsh").toBool();
        if (host.name.isEmpty())
            host.name = host.host;
        if (remoteTargetOk(host.user, host.host, host.port))
            m_saved.append(host);
    }
    for (const auto &value : root.value("logins").toArray()) {
        const auto obj = value.toObject();
        const auto id = obj.value("id").toString();
        const auto user = obj.value("user").toString();
        if (!id.startsWith(QStringLiteral("ts:")))
            continue;
        if (!remoteTargetOk(QStringLiteral("peer"), id.mid(3), 22) || !accountNameOk(user))
            continue;
        m_loginUsers.insert(id, user);
    }
}

void Backend::writeSavedHosts() const {
    const auto path = hostsPath();
    if (path.isEmpty())
        return;
    QDir().mkpath(QFileInfo(path).absolutePath());
    QJsonArray list;
    for (const auto &host : m_saved) {
        list.append(QJsonObject{{"name", host.name},
                                {"user", host.user},
                                {"host", host.host},
                                {"port", host.port},
                                {"via", host.via},
                                {"tailscaleSsh", host.tailscaleSsh}});
    }
    QJsonArray logins;
    for (auto it = m_loginUsers.cbegin(); it != m_loginUsers.cend(); ++it) {
        if (!it.key().startsWith(QStringLiteral("ts:")) || !accountNameOk(it.value()))
            continue;
        if (!remoteTargetOk(QStringLiteral("peer"), it.key().mid(3), 22))
            continue;
        logins.append(QJsonObject{{"id", it.key()}, {"user", it.value()}});
    }
    QSaveFile out(path);
    if (!out.open(QIODevice::WriteOnly))
        return;
    out.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    out.write(QJsonDocument(QJsonObject{{"hosts", list}, {"logins", logins}}).toJson());
    out.commit();
}

void Backend::publishHosts() {
    m_hostRows.clear();
    m_hostRows << QVariantMap{{"id", "local"},
                              {"name", "This computer"},
                              {"detail", "the computer running this window"},
                              {"via", ""},
                              {"user", ""},
                              {"password", ""}};
    for (const auto &peer : m_peers) {
        const auto id = QStringLiteral("ts:") + peer.host;
        const auto storedUser = m_loginUsers.value(id);
        const auto shown = storedUser.isEmpty() ? localUser() : storedUser;
        auto detail = peer.host;
        detail += QStringLiteral(" · ") + shown;
        detail += peer.tailscaleSsh ? QStringLiteral(" · Tailscale SSH") : QStringLiteral(" · tailscale");
        m_hostRows << QVariantMap{{"id", id},
                                  {"name", peer.name},
                                  {"detail", detail},
                                  {"via", "tailscale"},
                                  {"user", shown},
                                  {"password", m_loginPasswords.value(id)}};
    }
    for (const auto &saved : m_saved) {
        m_hostRows << QVariantMap{{"id", "saved:" + saved.user + "@" + saved.host + ":" + QString::number(saved.port)},
                                  {"name", saved.name},
                                  {"detail", saved.user + "@" + saved.host},
                                  {"via", saved.via},
                                  {"user", saved.user},
                                  {"password", ""}};
    }
    emit hostChanged();
}

void Backend::refreshHosts() {
    auto apply = [this](const CommandResult &status) {
        m_library.tailscaleStatus = (!status.missing && status.code == 0) ? status.out : QString();
        m_peers = tailscalePeers(m_library.tailscaleStatus);
        publishHosts();
    };
    if (!m_deferProbes || !m_owned) {
        apply(m_localCommands->run("tailscale", {"status", "--json"}, {}, m_localCommands->probeTimeoutMs()));
        return;
    }
    auto commands = m_owned;
    const int wave = ++m_hostWave;
    QPointer<Backend> self(this);
    QThreadPool::globalInstance()->start([commands, wave, self] {
        const auto status = commands->run("tailscale", {"status", "--json"}, {}, commands->probeTimeoutMs());
        auto *app = QCoreApplication::instance();
        if (!app)
            return;
        QMetaObject::invokeMethod(app, [self, wave, status] {
            if (!self || wave != self->m_hostWave)
                return;
            self->m_library.tailscaleStatus = (!status.missing && status.code == 0) ? status.out : QString();
            self->m_peers = tailscalePeers(self->m_library.tailscaleStatus);
            self->publishHosts();
        }, Qt::QueuedConnection);
    });
}

RemoteHost Backend::hostById(const QString &id) const {
    if (id.startsWith("ts:")) {
        const auto name = id.mid(3);
        for (const auto &peer : m_peers) {
            if (peer.host == name)
                return peer;
        }
    }
    if (id.startsWith("saved:")) {
        const auto rest = id.mid(6);
        for (const auto &saved : m_saved) {
            if (rest == saved.user + "@" + saved.host + ":" + QString::number(saved.port))
                return saved;
        }
    }
    return {};
}

bool Backend::beginConnect(const RemoteHost &host) {
    auto target = host;
    if (target.user.isEmpty())
        target.user = localUser();
    if (!m_injectedLink && !remoteTargetOk(target.user, target.host, target.port)) {
        m_trustNextConnect = false;
        setError(QStringLiteral("That computer needs a user and a plain host name."));
        return false;
    }
    const int wave = ++m_wave;
    ++m_s3Wave;
    m_s3Ready = false;
    m_sessionsReady[0] = m_sessionsReady[1] = m_sessionsReady[2] = false;
    m_restoreTitle = m_hostTitle;
    m_connecting = true;
    const bool trustNext = m_trustNextConnect;
    m_trustNextConnect = false;
    m_pendingUser = target.user;
    m_pendingHost = target.host;
    m_pendingPassword = target.password;
    m_pendingPort = target.port;
    m_pendingTailscaleSsh = target.tailscaleSsh;
    const auto label = target.name.isEmpty() ? target.host : target.name;
    m_hostTitle = QStringLiteral("Connecting to %1").arg(label);
    m_notice = QStringLiteral("Reading the share files.");
    m_canInstall = false;
    m_canTrustHost = false;
    emit hostChanged();
    touch();

    const auto login = localUser();
    QPointer<Backend> self(this);
    QThreadPool::globalInstance()->start([target, login, wave, trustNext, self] {
        auto attempt = [trustNext](RemoteHost candidate) {
            auto link = std::make_shared<SshLink>(candidate.user, candidate.host, candidate.port, candidate.tailscaleSsh,
                                                  candidate.password);
            if (trustNext)
                link->trustNextKey();
            return std::pair<std::shared_ptr<RemoteLink>, RemoteNeed>(link, probeRemote(link.get()));
        };
        auto tried = attempt(target);
        auto chosen = target;
        const auto denied = QStringLiteral("does not permit you to SSH as user");
        // A typed password belongs to that user. Do not retry it as root.
        if (!tried.second.connected && tried.second.error.contains(denied) && chosen.password.isEmpty()
            && chosen.user == login && chosen.user != QStringLiteral("root")) {
            auto root = chosen;
            root.user = QStringLiteral("root");
            const auto firstError = tried.second.error;
            tried = attempt(root);
            chosen = root;
            if (!tried.second.connected && tried.second.error.contains(denied))
                tried.second.error = firstError + QStringLiteral("\nType the SSH user this tailnet allows. Root was refused too.");
        }
        ConnectResult result;
        result.wave = wave;
        result.need = tried.second;
        result.host = chosen;
        if (result.need.connected) {
            const auto pulled = tried.first->exec(remoteBundleArgv(), {}, 20000);
            const auto message = pulled.err + pulled.out;
            if (pulled.code != 0) {
                if (message.contains(QStringLiteral("a password is required")) || message.contains(QStringLiteral("sudo")))
                    result.pullError = QStringLiteral("The SSH user needs passwordless sudo to read the share files.");
                else
                    result.pullError = message.trimmed().isEmpty() ? QStringLiteral("Could not read the share files.")
                                                                   : message.trimmed();
            } else {
                result.haveBundle = true;
                result.bundle = pulled.out.toUtf8();
            }
        }
        auto link = tried.first;
        auto *app = QCoreApplication::instance();
        if (!app)
            return;
        QMetaObject::invokeMethod(
            app, [self, result, link] {
                if (!self)
                    return;
                self->applyConnect(result, link);
            },
            Qt::QueuedConnection);
    });
    return true;
}

void Backend::applyConnect(const ConnectResult &result, const std::shared_ptr<RemoteLink> &link) {
    if (result.wave != m_wave)
        return;
    m_pendingUser = result.host.user;
    m_pendingHost = result.host.host;
    m_pendingPassword = result.host.password;
    m_pendingPort = result.host.port;
    m_pendingTailscaleSsh = result.host.tailscaleSsh;
    m_connecting = false;
    if (!result.need.connected) {
        // A failed first connection has no mirror. A failed switch leaves the
        // computer that was already open, including its SSH link.
        if (!m_mirror) {
            m_linkShared.reset();
            m_link = m_injectedLink;
            m_commands = m_localCommands;
            m_library.setCommands(m_commands);
            m_hostTitle = QStringLiteral("This computer");
        } else {
            m_hostTitle = m_restoreTitle.isEmpty() ? QStringLiteral("This computer") : m_restoreTitle;
        }
        m_notice = m_library.notice;
        m_canTrustHost = result.need.hostKeyDenied;
        m_canInstall = false;
        m_needsText.clear();
        setError(result.need.error);
        emit hostChanged();
        touch();
        return;
    }
    m_linkShared = link;
    m_link = link.get();
    m_mirror = std::make_unique<QTemporaryDir>();
    if (!m_mirror->isValid()) {
        setError(QStringLiteral("Could not keep a local copy of that computer."));
        m_hostTitle = QStringLiteral("This computer");
        emit hostChanged();
        return;
    }
    QString pullError = result.pullError;
    if (result.haveBundle)
        writeRemoteBundle(result.bundle, m_mirror->path(), &pullError);
    m_remoteCommands = std::make_shared<RemoteCommands>(m_link);
    m_commands = m_remoteCommands.get();
    m_library.setCommands(m_commands);
    m_library.setProfile(result.need.profile);
    m_library.setRoot(m_mirror->path());
    m_root = m_mirror->path();
    m_remoteProfile = result.need.profile;
    m_hostTitle = result.host.name.isEmpty() ? result.host.host : result.host.name;
    m_neededPackages = result.need.packages;
    m_canInstall = result.need.sudo && !result.need.packages.isEmpty();
    m_canTrustHost = false;
    if (!result.need.sudo)
        m_needsText = result.need.error + QStringLiteral("\n\n") + result.need.command;
    else if (!result.need.packages.isEmpty())
        m_needsText = QStringLiteral("These packages are missing on %1:\n").arg(m_hostTitle) + result.need.command;
    else
        m_needsText.clear();
    finishReload(result.wave, pullError);
    m_connecting = false;
    if (!result.need.sudo)
        setError(result.need.error);
    if (!m_needsText.isEmpty())
        emit needsReady();
    emit hostChanged();
    emit computerReady();
}

void Backend::scheduleRemoteReload(int wave) {
    auto link = m_linkShared;
    if (!link) {
        finishReload(wave, QStringLiteral("Could not read the share files."));
        return;
    }
    QPointer<Backend> self(this);
    QThreadPool::globalInstance()->start([link, wave, self] {
        QString pullError;
        QByteArray bundle;
        bool haveBundle = false;
        const auto result = link->exec(remoteBundleArgv(), {}, 20000);
        const auto message = result.err + result.out;
        if (result.code != 0) {
            if (message.contains(QStringLiteral("a password is required")) || message.contains(QStringLiteral("sudo")))
                pullError = QStringLiteral("The SSH user needs passwordless sudo to read the share files.");
            else
                pullError = message.trimmed().isEmpty() ? QStringLiteral("Could not read the share files.") : message.trimmed();
        } else {
            haveBundle = true;
            bundle = result.out.toUtf8();
        }
        auto *app = QCoreApplication::instance();
        if (!app)
            return;
        QMetaObject::invokeMethod(
            app, [self, wave, bundle, haveBundle, pullError] {
                if (!self || wave != self->m_wave || !self->m_mirror)
                    return;
                QString error = pullError;
                if (haveBundle)
                    writeRemoteBundle(bundle, self->m_mirror->path(), &error);
                self->m_library.setRoot(self->m_mirror->path());
                self->m_root = self->m_mirror->path();
                self->finishReload(wave, error);
            },
            Qt::QueuedConnection);
    });
}

void Backend::useLocal() {
    ++m_wave;
    ++m_s3Wave;
    m_connecting = false;
    m_mirror.reset();
    m_remoteCommands.reset();
    m_linkShared.reset();
    m_link = m_injectedLink;
    m_commands = m_localCommands;
    m_library.setCommands(m_commands);
    m_library.setRoot(m_appRoot);
    m_library.setProfile(m_localProfile);
    m_root = m_appRoot;
    m_hostTitle = QStringLiteral("This computer");
    m_pendingPassword.clear();
    m_needsText.clear();
    m_neededPackages.clear();
    m_canInstall = false;
    m_canTrustHost = false;
    publishHosts();
}

bool Backend::connectRemote(const RemoteHost &host) {
    auto target = host;
    if (target.user.isEmpty())
        target.user = localUser();
    if (m_deferProbes)
        return beginConnect(target);
    if (connectRemoteUser(target))
        return true;
    // A tailnet often allows root and rejects the login running this window.
    // Retry that once. A user typed in the box is left as they wrote it.
    const auto denied = m_error;
    if (target.password.isEmpty() && denied.contains(QStringLiteral("does not permit you to SSH as user"))
        && target.user == localUser() && target.user != QStringLiteral("root")) {
        target.user = QStringLiteral("root");
        if (connectRemoteUser(target))
            return true;
        if (m_error.contains(QStringLiteral("does not permit you to SSH as user"))) {
            setError(denied + QStringLiteral("\nType the SSH user this tailnet allows. Root was refused too."));
        }
    }
    return false;
}

bool Backend::connectRemoteUser(const RemoteHost &host) {
    auto target = host;
    if (target.user.isEmpty())
        target.user = localUser();
    if (!m_injectedLink) {
        if (!remoteTargetOk(target.user, target.host, target.port)) {
            setError(QStringLiteral("That computer needs a user and a plain host name."));
            return false;
        }
        m_linkShared = std::make_shared<SshLink>(target.user, target.host, target.port, target.tailscaleSsh, target.password);
        m_link = m_linkShared.get();
        if (m_trustNextConnect) {
            static_cast<SshLink *>(m_link)->trustNextKey();
            m_trustNextConnect = false;
        }
    }
    m_pendingUser = target.user;
    m_pendingHost = target.host;
    m_pendingPassword = target.password;
    m_pendingPort = target.port;
    m_pendingTailscaleSsh = target.tailscaleSsh;
    const auto need = probeRemote(m_link);
    if (!need.connected) {
        m_canTrustHost = need.hostKeyDenied;
        m_canInstall = false;
        m_needsText.clear();
        setError(need.error);
        emit hostChanged();
        return false;
    }
    m_mirror = std::make_unique<QTemporaryDir>();
    if (!m_mirror->isValid()) {
        setError(QStringLiteral("Could not keep a local copy of that computer."));
        return false;
    }
    m_remoteCommands = std::make_shared<RemoteCommands>(m_link);
    m_commands = m_remoteCommands.get();
    m_library.setCommands(m_commands);
    m_library.setProfile(need.profile);
    m_remoteProfile = need.profile;
    m_hostTitle = target.name.isEmpty() ? target.host : target.name;
    m_neededPackages = need.packages;
    m_canInstall = need.sudo && !need.packages.isEmpty();
    m_canTrustHost = false;
    if (!need.sudo)
        m_needsText = need.error + QStringLiteral("\n\n") + need.command;
    else if (!need.packages.isEmpty())
        m_needsText = QStringLiteral("These packages are missing on %1:\n").arg(m_hostTitle) + need.command;
    else
        m_needsText.clear();
    reload();
    if (!need.sudo)
        setError(need.error);
    if (!m_needsText.isEmpty())
        emit needsReady();
    emit computerReady();
    return true;
}

bool Backend::useHost(const QString &id, const QString &user, const QString &password) {
    // Shares found in smb.conf mark the window unsaved as soon as it connects.
    // Leaving writes nothing, so that flag cannot trap the window on that
    // computer. An edit still has an undo entry, and that still waits.
    if (m_dirty && !m_undo.isEmpty()) {
        setError(QStringLiteral("Save or discard changes before switching computers."));
        return false;
    }
    if (id.isEmpty() || id == "local") {
        useLocal();
        reload();
        emit computerReady();
        return true;
    }
    auto host = hostById(id);
    if (host.host.isEmpty()) {
        setError(QStringLiteral("That computer is not in the list."));
        return false;
    }
    if (id.startsWith(QStringLiteral("ts:"))) {
        const auto storedUser = m_loginUsers.value(id);
        const auto chosen = user.trimmed().isEmpty() ? storedUser : user.trimmed();
        if (!chosen.isEmpty()) {
            if (!accountNameOk(chosen)) {
                setError(QStringLiteral("The SSH user has to be a lowercase account name."));
                return false;
            }
            host.user = chosen;
        }
        host.password = password.isEmpty() ? m_loginPasswords.value(id) : password;
    } else {
        const auto chosen = user.trimmed();
        if (!chosen.isEmpty()) {
            if (!accountNameOk(chosen)) {
                setError(QStringLiteral("The SSH user has to be a lowercase account name."));
                return false;
            }
            host.user = chosen;
        }
        if (!password.isEmpty())
            host.password = password;
    }
    if (host.password.contains(u'\n') || host.password.contains(u'\r')) {
        setError(QStringLiteral("The SSH password cannot contain a line break."));
        return false;
    }
    // Tailscale SSH authenticates the tailnet identity, not this password.
    if (!host.password.isEmpty())
        host.tailscaleSsh = false;
    return connectRemote(host);
}

void Backend::setHostLogin(const QString &id, const QString &user, const QString &password) {
    if (!id.startsWith(QStringLiteral("ts:")))
        return;
    if (password.contains(u'\n') || password.contains(u'\r'))
        return;
    const auto trimmed = user.trimmed();
    const auto previous = m_loginUsers.value(id);
    if (trimmed.isEmpty())
        m_loginUsers.remove(id);
    else if (accountNameOk(trimmed))
        m_loginUsers.insert(id, trimmed);
    if (password.isEmpty())
        m_loginPasswords.remove(id);
    else
        m_loginPasswords.insert(id, password);
    if (m_loginUsers.value(id) != previous)
        writeSavedHosts();
}

bool Backend::addHost(const QString &user, const QString &hostName, int port, const QString &password) {
    const auto userName = user.trimmed().isEmpty() ? localUser() : user.trimmed();
    const auto host = hostName.trimmed();
    const int actualPort = port == 0 ? 22 : port;
    if (!remoteTargetOk(userName, host, actualPort)) {
        setError(QStringLiteral("Use a plain user, host, and port."));
        return false;
    }
    if (password.contains(u'\n') || password.contains(u'\r')) {
        setError(QStringLiteral("The SSH password cannot contain a line break."));
        return false;
    }
    if (m_dirty && !m_undo.isEmpty()) {
        setError(QStringLiteral("Save or discard changes before switching computers."));
        return false;
    }
    RemoteHost remote;
    remote.name = host.section('.', 0, 0);
    remote.user = userName;
    remote.host = host;
    remote.port = actualPort;
    remote.via = "ssh";
    remote.password = password;
    bool replaced = false;
    for (auto &saved : m_saved) {
        if (saved.user == remote.user && saved.host == remote.host && saved.port == remote.port) {
            saved = remote;
            replaced = true;
        }
    }
    if (!replaced)
        m_saved.append(remote);
    // Keep the host address and user for later, but never persist the password.
    for (auto &saved : m_saved) {
        if (saved.user == remote.user && saved.host == remote.host && saved.port == remote.port)
            saved.password.clear();
    }
    writeSavedHosts();
    publishHosts();
    return connectRemote(remote);
}

void Backend::clearSmbShares() {
    ++m_smbWave;
    m_smbHost.clear();
    m_smbError.clear();
    m_smbStatus.clear();
    m_smbShares.clear();
    m_smbScanning = false;
    emit smbChanged();
}

void Backend::discoverSmbShares(const QString &hostName, const QString &userName, const QString &password) {
    const auto host = hostName.trimmed();
    const auto user = userName.trimmed();
    if (!smbHostOk(host)) {
        m_smbError = QStringLiteral("Enter a host name or IPv4 address.");
        m_smbShares.clear();
        m_smbStatus.clear();
        m_smbScanning = false;
        emit smbChanged();
        return;
    }
    const auto credentialError = smbCredentialError(user, password);
    if (!credentialError.isEmpty()) {
        m_smbError = credentialError;
        m_smbShares.clear();
        m_smbStatus.clear();
        m_smbScanning = false;
        emit smbChanged();
        return;
    }

    const int wave = ++m_smbWave;
    m_smbHost = host;
    m_smbError.clear();
    m_smbShares.clear();
    m_smbStatus = QStringLiteral("Looking for SMB shares…");
    m_smbScanning = true;
    emit smbChanged();

    QPointer<Backend> self(this);
    QThreadPool::globalInstance()->start([host, user, password, wave, self] {
        auto result = scanSmbShares(host, user, password);
        for (auto &share : result.shares) {
            auto map = share.toMap();
            map.insert(QStringLiteral("host"), host);
            share = map;
        }
        auto *app = QCoreApplication::instance();
        if (!app)
            return;
        QMetaObject::invokeMethod(
            app,
            [self, wave, result] {
                if (!self || wave != self->m_smbWave)
                    return;
                self->m_smbScanning = false;
                self->m_smbStatus.clear();
                self->m_smbShares = result.shares;
                self->m_smbError = result.error;
                emit self->smbChanged();
            },
            Qt::QueuedConnection);
    });
}

void Backend::scanSmbNetwork(const QString &userName, const QString &password) {
    const auto user = userName.trimmed();
    const auto credentialError = smbCredentialError(user, password);
    if (!credentialError.isEmpty()) {
        m_smbError = credentialError;
        m_smbShares.clear();
        m_smbStatus.clear();
        m_smbScanning = false;
        emit smbChanged();
        return;
    }

    const int wave = ++m_smbWave;
    m_smbHost.clear();
    m_smbError.clear();
    m_smbShares.clear();
    m_smbStatus = QStringLiteral("Scanning this computer's local network for SMB and Samba…");
    m_smbScanning = true;
    emit smbChanged();

    QPointer<Backend> self(this);
    QThreadPool::globalInstance()->start([user, password, wave, self] {
        QString planError;
        const auto hosts = planLanHosts(&planError);
        QVariantList shares;
        QString error = planError;
        if (!hosts.isEmpty()) {
            const auto servers = hostsWithSmb(hosts);
            if (servers.isEmpty()) {
                error = QStringLiteral("No SMB or Samba servers were found on the local network.");
            } else {
                for (const auto &host : servers) {
                    const auto result = scanSmbShares(host, user, password, 8000);
                    for (const auto &share : result.shares) {
                        auto map = share.toMap();
                        map.insert(QStringLiteral("host"), host);
                        shares.append(map);
                    }
                }
                if (shares.isEmpty())
                    error = QStringLiteral("SMB servers answered, but none listed a visible share. Try a username and password.");
                else
                    error.clear();
            }
        }
        auto *app = QCoreApplication::instance();
        if (!app)
            return;
        QMetaObject::invokeMethod(
            app,
            [self, wave, shares, error] {
                if (!self || wave != self->m_smbWave)
                    return;
                self->m_smbScanning = false;
                self->m_smbStatus.clear();
                self->m_smbShares = shares;
                self->m_smbError = error;
                emit self->smbChanged();
            },
            Qt::QueuedConnection);
    });
}

bool Backend::openSmbShare(int index) {
    if (index < 0 || index >= m_smbShares.size())
        return false;
    const auto share = m_smbShares.at(index).toMap();
    const auto name = share.value(QStringLiteral("name")).toString();
    const auto host = share.value(QStringLiteral("host")).toString().isEmpty() ? m_smbHost
                                                                                : share.value(QStringLiteral("host")).toString();
    if (name.isEmpty() || host.isEmpty())
        return false;
    QUrl url;
    url.setScheme(QStringLiteral("smb"));
    url.setHost(host);
    url.setPath(QStringLiteral("/") + name);
    const auto location = url.toString(QUrl::FullyEncoded);
    // This desktop has no smb:// handler, so Nautilus has to be asked directly.
    const auto nautilus = QStandardPaths::findExecutable(QStringLiteral("nautilus"));
    if (!nautilus.isEmpty() && QProcess::startDetached(nautilus, {QStringLiteral("--new-window"), location}))
        return true;
    if (QDesktopServices::openUrl(url))
        return true;
    const auto gio = QStandardPaths::findExecutable(QStringLiteral("gio"));
    if (!gio.isEmpty() && QProcess::startDetached(gio, {QStringLiteral("open"), location}))
        return true;
    m_smbError = QStringLiteral("Could not open the share. Install a file manager with SMB support (gvfs-smb on Arch).");
    emit smbChanged();
    return false;
}

bool Backend::leaveComputer() {
    if (!remote())
        return true;
    if (m_browsing)
        setBrowsing(false);
    useLocal();
    reload();
    return true;
}

bool Backend::installNeeds() {
    // Shares out of smb.conf mark the window unsaved as soon as it connects.
    // Saving that migration starts smbd, so the flag cannot block the install
    // that provides smbd. An edit still has an undo entry, and that still waits.
    if (m_dirty && !m_undo.isEmpty()) {
        setError(QStringLiteral("Save or discard changes before installing packages."));
        return false;
    }
    if (!m_link || !m_canInstall || m_neededPackages.isEmpty()) {
        setError(QStringLiteral("There is nothing to install, or that computer still needs a sudo password."));
        return false;
    }
    QString error;
    if (!installRemotePackages(m_link, m_remoteProfile, m_neededPackages, &error)) {
        setError(error);
        return false;
    }
    const auto need = probeRemote(m_link);
    m_remoteProfile = need.profile;
    m_library.setProfile(need.profile);
    m_neededPackages = need.packages;
    m_canInstall = need.connected && need.sudo && !need.packages.isEmpty();
    if (!need.connected)
        m_needsText = need.error;
    else if (!need.sudo)
        m_needsText = need.error + QStringLiteral("\n\n") + need.command;
    else if (!need.packages.isEmpty())
        m_needsText = QStringLiteral("These packages are missing on %1:\n").arg(m_hostTitle) + need.command;
    else
        m_needsText.clear();
    reload();
    if (!need.connected || !need.sudo)
        setError(need.error);
    else
        setError({});
    if (!m_needsText.isEmpty())
        emit needsReady();
    emit hostChanged();
    return need.connected && need.sudo && need.packages.isEmpty();
}

bool Backend::trustHost() {
    if (!m_canTrustHost)
        return false;
    // The next SshLink is created inside the connect. The flag has to ride
    // along, because the link that just failed is replaced before it runs again.
    m_trustNextConnect = true;
    RemoteHost host;
    host.user = m_pendingUser;
    host.host = m_pendingHost;
    host.port = m_pendingPort;
    host.password = m_pendingPassword;
    host.tailscaleSsh = m_pendingTailscaleSsh;
    host.name = m_pendingHost.section('.', 0, 0);
    return connectRemote(host);
}
