#pragma once

#include <QVariantMap>

#include "filepicker.h"

// Portal file chooser follows Omacut (MIT, David Heinemeier Hansson).
class PortalFilePicker : public FilePicker {
    Q_OBJECT

public:
    explicit PortalFilePicker(QObject *parent = nullptr);

    void chooseFolder(const QString &title, const QString &currentFolder) override;
    void chooseNewFile(const QString &title, const QString &currentFolder, const QString &suggestedName) override;

private slots:
    void handleResponse(uint response, const QVariantMap &results);

private:
    enum class Action { None, Folder, File };

    void requestFile(const QString &method, const QString &title, QVariantMap options, Action action);
    bool connectToRequestPath(const QString &path);
    void clearPending();

    QString m_pendingPath;
    Action m_pendingAction = Action::None;
};
