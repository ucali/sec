TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
CONFIG += c++11

TARGET = TestSec

INCLUDEPATH += $$_PRO_FILE_PWD_/..
INCLUDEPATH += $$_PRO_FILE_PWD_/Catch/include
INCLUDEPATH += $$_PRO_FILE_PWD_/..



CONFIG(debug, debug|release) {
    win32 {
            LIBS += -L$$_PRO_FILE_PWD_/../cryptopp/x64/Output/Debug
    }
    LIBS += -lcryptlib
} else {
    win32 {
            LIBS += -L$$_PRO_FILE_PWD_/../cryptopp/x64/Output/Release
    }
    LIBS += -lcryptlib
}

SOURCES += test.cpp \

CONFIG(debug, debug|release) {
        TARGET = $$join(TARGET,,,d)
}

DESTDIR = $$_PRO_FILE_PWD_/bin
