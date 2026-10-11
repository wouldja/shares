QT += core gui qml quick quickcontrols2 dbus

CONFIG += c++17 release
TARGET = shares
TEMPLATE = app

HEADERS += \
    src/backend.h \
    src/config.h \
    src/filepicker.h \
    src/portalfilepicker.h \
    src/remote.h \
    src/store.h \
    src/theme.h

SOURCES += \
    src/main.cpp \
    src/backend.cpp \
    src/config.cpp \
    src/portalfilepicker.cpp \
    src/remote.cpp \
    src/store.cpp \
    src/theme.cpp

RESOURCES += src/resources.qrc
