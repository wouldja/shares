// Privileged apply. Polkit starts this binary. It reads a model on stdin,
// rebuilds the plan from the files on disk, and refuses anything outside the
// allowlist. A file body from the caller is not applied.

#include <QCoreApplication>
#include <QFile>
#include <cstdio>

#include "store.h"

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    QString root = QStringLiteral("/");
    for (int i = 1; i < argc; ++i) {
        if (qstrcmp(argv[i], "--root") == 0 && i + 1 < argc)
            root = QString::fromLocal8Bit(argv[++i]);
    }
    QFile in;
    if (!in.open(stdin, QIODevice::ReadOnly))
        return 1;
    QString error;
    QString output;
    Commands commands;
    if (!applyOperation(root, in.readAll(), &commands, &error, &output)) {
        fprintf(stderr, "%s\n", qPrintable(error));
        return 1;
    }
    fprintf(stdout, "%s", qPrintable(output));
    return 0;
}
