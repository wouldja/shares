#pragma once

#include <QObject>
#include <QString>

// A folder or new-file dialog. Tests supply a fake. The real window uses the
// desktop portal so the browser is the system one, with Create Folder and
// both keyboard and mouse.
class FilePicker : public QObject {
    Q_OBJECT

public:
    explicit FilePicker(QObject *parent = nullptr) : QObject(parent) {}
    ~FilePicker() override = default;

    virtual void chooseFolder(const QString &title, const QString &currentFolder) = 0;
    virtual void chooseNewFile(const QString &title, const QString &currentFolder, const QString &suggestedName) = 0;

signals:
    void chosen(const QString &path);
    void cancelled();
    void failed(const QString &message);
};
