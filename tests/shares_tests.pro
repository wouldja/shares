QT += core gui quick quickcontrols2 testlib dbus
CONFIG += c++17 testcase
TARGET = shares_tests
TEMPLATE = app

INCLUDEPATH += ../src

HEADERS += ../src/backend.h ../src/config.h ../src/filepicker.h ../src/portalfilepicker.h ../src/store.h ../src/theme.h
SOURCES += shares_tests.cpp ../src/backend.cpp ../src/config.cpp ../src/portalfilepicker.cpp ../src/store.cpp ../src/theme.cpp
