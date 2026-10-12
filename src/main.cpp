// shares — publish folders over Samba, NFS, iSCSI, and S3.

#include <QCoreApplication>
#include <QFile>
#include <QGuiApplication>
#include <QIcon>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQmlError>
#include <QQuickStyle>
#include <QUrl>
#include <cstdio>

#include "backend.h"
#include "store.h"
#include "theme.h"

// Root-only half of a save. The graphical app sends a plan on stdin. This
// process re-checks every path and command before it writes or runs anything.
static int privilegedMain(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    QFile in;
    if (!in.open(stdin, QIODevice::ReadOnly))
        return 1;
    bool ok = false;
    const auto plan = planFromJson(in.readAll(), &ok);
    QString error;
    QString output;
    Commands commands;
    if (!ok || !applyPlan(QStringLiteral("/"), plan, &commands, &error, &output)) {
        fprintf(stderr, "%s\n", qPrintable(error.isEmpty() ? plan.error : error));
        return 1;
    }
    fprintf(stdout, "%s", qPrintable(output));
    return 0;
}

int main(int argc, char *argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (qstrcmp(argv[i], "--privileged") == 0)
            return privilegedMain(argc, argv);
    }

    QString root = QStringLiteral("/");
    for (int i = 1; i < argc; ++i) {
        if (qstrcmp(argv[i], "--root") == 0 && i + 1 < argc)
            root = QString::fromLocal8Bit(argv[++i]);
    }

    QGuiApplication app(argc, argv);
    app.setApplicationName("shares");
    app.setApplicationVersion("0.2.3");

    // Matches the window to shares.desktop, so the compositor (Wayland app_id)
    // and the launcher pick up the installed icon.
    app.setDesktopFileName("shares");
    app.setWindowIcon(QIcon::fromTheme("shares"));

    QQuickStyle::setStyle("Material");

    Theme theme;
    Backend backend(root);

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("theme", &theme);
    engine.rootContext()->setContextProperty("backend", &backend);
    // A failed window has to say why. Qt's own warning can be easy to miss.
    QObject::connect(&engine, &QQmlEngine::warnings, &app, [](const QList<QQmlError> &warnings) {
        for (const auto &warning : warnings)
            fprintf(stderr, "%s\n", qPrintable(warning.toString()));
    });
    engine.load(QUrl("qrc:/Main.qml"));
    if (engine.rootObjects().isEmpty())
        return 1;

    return app.exec();
}
