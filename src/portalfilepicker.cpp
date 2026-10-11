// Portal file chooser follows Omacut (MIT, David Heinemeier Hansson).
#include "portalfilepicker.h"

#include <QDBusConnection>
#include <QDBusInterface>
#include <QDBusObjectPath>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QRandomGenerator>
#include <QUrl>

namespace {

QString portalToken() {
    return QStringLiteral("shares_%1").arg(QRandomGenerator::global()->generate());
}

// The portal wants the folder as a nul-terminated byte array, not a string.
QByteArray portalPathBytes(const QString &path) {
    QByteArray bytes = path.toUtf8();
    bytes.append('\0');
    return bytes;
}

QString localPath(const QString &uri) {
    const QUrl url(uri);
    if (!url.isLocalFile())
        return {};
    auto path = url.toLocalFile();
    if (path.size() > 1 && path.endsWith('/'))
        path.chop(1);
    return path;
}

} // namespace

PortalFilePicker::PortalFilePicker(QObject *parent) : FilePicker(parent) {}

void PortalFilePicker::chooseFolder(const QString &title, const QString &currentFolder) {
    QVariantMap options;
    options.insert(QStringLiteral("accept_label"), QStringLiteral("Select"));
    options.insert(QStringLiteral("modal"), true);
    options.insert(QStringLiteral("multiple"), false);
    // Select-folder mode is what shows Create Folder. Open-file mode hides it.
    options.insert(QStringLiteral("directory"), true);
    options.insert(QStringLiteral("current_folder"), portalPathBytes(currentFolder));
    requestFile(QStringLiteral("OpenFile"), title, options, Action::Folder);
}

void PortalFilePicker::chooseNewFile(const QString &title, const QString &currentFolder, const QString &suggestedName) {
    QVariantMap options;
    options.insert(QStringLiteral("accept_label"), QStringLiteral("Select"));
    options.insert(QStringLiteral("modal"), true);
    options.insert(QStringLiteral("current_folder"), portalPathBytes(currentFolder));
    options.insert(QStringLiteral("current_name"), suggestedName);
    // Save mode can name an image that does not exist yet, and still offers Create Folder.
    requestFile(QStringLiteral("SaveFile"), title, options, Action::File);
}

bool PortalFilePicker::connectToRequestPath(const QString &path) {
    m_pendingPath = path;
    return QDBusConnection::sessionBus().connect(
        QStringLiteral("org.freedesktop.portal.Desktop"), m_pendingPath,
        QStringLiteral("org.freedesktop.portal.Request"), QStringLiteral("Response"), this,
        SLOT(handleResponse(uint,QVariantMap)));
}

void PortalFilePicker::requestFile(const QString &method, const QString &title, QVariantMap options, Action action) {
    if (m_pendingAction != Action::None)
        return;

    QDBusConnection bus = QDBusConnection::sessionBus();
    QDBusInterface portal(QStringLiteral("org.freedesktop.portal.Desktop"),
                          QStringLiteral("/org/freedesktop/portal/desktop"),
                          QStringLiteral("org.freedesktop.portal.FileChooser"), bus);
    if (!portal.isValid()) {
        emit failed(QStringLiteral("The folder browser is not available. Type the path, or install xdg-desktop-portal."));
        return;
    }

    // Subscribe before the call. A fast response can arrive while the match
    // rule is still being installed if we wait for the method reply.
    const QString token = portalToken();
    options.insert(QStringLiteral("handle_token"), token);
    QString sender = bus.baseService().mid(1);
    sender.replace(QLatin1Char('.'), QLatin1Char('_'));
    const QString predictedPath = QStringLiteral("/org/freedesktop/portal/desktop/request/%1/%2").arg(sender, token);

    m_pendingAction = action;
    if (!connectToRequestPath(predictedPath)) {
        clearPending();
        emit failed(QStringLiteral("Could not listen for the folder browser."));
        return;
    }

    auto *watcher = new QDBusPendingCallWatcher(portal.asyncCall(method, QString(), title, options), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, watcher]() {
        QDBusPendingReply<QDBusObjectPath> reply = *watcher;
        watcher->deleteLater();
        if (m_pendingAction == Action::None)
            return;
        if (reply.isError()) {
            clearPending();
            emit failed(QStringLiteral("The folder browser failed: %1").arg(reply.error().message()));
            return;
        }
        const QString actualPath = reply.value().path();
        if (actualPath != m_pendingPath) {
            QDBusConnection::sessionBus().disconnect(
                QStringLiteral("org.freedesktop.portal.Desktop"), m_pendingPath,
                QStringLiteral("org.freedesktop.portal.Request"), QStringLiteral("Response"), this,
                SLOT(handleResponse(uint,QVariantMap)));
            if (!connectToRequestPath(actualPath)) {
                clearPending();
                emit failed(QStringLiteral("Could not listen for the folder browser."));
            }
        }
    });
}

void PortalFilePicker::handleResponse(uint response, const QVariantMap &results) {
    clearPending();
    if (response != 0) {
        emit cancelled();
        return;
    }
    const QStringList uris = results.value(QStringLiteral("uris")).toStringList();
    if (uris.isEmpty()) {
        emit cancelled();
        return;
    }
    const auto path = localPath(uris.first());
    if (path.isEmpty()) {
        emit failed(QStringLiteral("That location is not a local path."));
        return;
    }
    emit chosen(path);
}

void PortalFilePicker::clearPending() {
    if (!m_pendingPath.isEmpty()) {
        QDBusConnection::sessionBus().disconnect(
            QStringLiteral("org.freedesktop.portal.Desktop"), m_pendingPath,
            QStringLiteral("org.freedesktop.portal.Request"), QStringLiteral("Response"), this,
            SLOT(handleResponse(uint,QVariantMap)));
    }
    m_pendingPath.clear();
    m_pendingAction = Action::None;
}
