#include "network/InstalledHelperBootstrap.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QtTest>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace interceptor;

class M6InstalledHelperBootstrapTests final : public QObject {
    Q_OBJECT

    static uid_t ownerOf(const QString &path) {
        struct stat info{};
        const QByteArray encoded = QFile::encodeName(path);
        if (::stat(encoded.constData(), &info) != 0)
            qFatal("Cannot stat synthetic state directory");
        return info.st_uid;
    }

    static QString canonical(const QString &path) { return QFileInfo(path).canonicalFilePath(); }

    static void setPrivateMode(const QString &path) {
        const QByteArray encoded = QFile::encodeName(path);
        if (::chmod(encoded.constData(), 0700) != 0)
            qFatal("Cannot set synthetic state directory mode");
    }

  private slots:
    void opensOnlyTrustedPrivateDirectoryAndOwnsCloexecDescriptor() {
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        setPrivateMode(temporary.path());

        QString error = QStringLiteral("stale-error");
        int descriptor = -1;
        {
            auto directory = InstalledHelperStateDirectory::open(canonical(temporary.path()),
                                                                 ownerOf(temporary.path()), &error);
            QVERIFY2(directory.has_value(), qPrintable(error));
            QVERIFY(error.isEmpty());
            QCOMPARE(directory->canonicalPath(), canonical(temporary.path()));

            descriptor = directory->descriptor();
            QVERIFY(descriptor >= 0);
            struct stat info{};
            QCOMPARE(::fstat(descriptor, &info), 0);
            QVERIFY(S_ISDIR(info.st_mode));
            QCOMPARE(info.st_uid, ownerOf(temporary.path()));
            QCOMPARE(info.st_mode & 07777, mode_t(0700));
            const int flags = ::fcntl(descriptor, F_GETFD);
            QVERIFY(flags >= 0);
            QVERIFY((flags & FD_CLOEXEC) != 0);

            auto moved = std::move(*directory);
            QCOMPARE(directory->descriptor(), -1);
            QCOMPARE(moved.descriptor(), descriptor);
            QVERIFY(::fcntl(descriptor, F_GETFD) >= 0);
        }
        QCOMPARE(::fcntl(descriptor, F_GETFD), -1);
    }

    void rejectsNonAbsoluteMissingAndNonCanonicalPaths() {
        QString error;
        QVERIFY(!InstalledHelperStateDirectory::open(QStringLiteral("relative/state"), geteuid(),
                                                     &error));
        QVERIFY(!error.isEmpty());
        const QString embeddedNul = QStringLiteral("/safe/state\0/ignored");
        QVERIFY(!InstalledHelperStateDirectory::open(embeddedNul, geteuid(), &error));
        QVERIFY(!error.isEmpty());

        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        const QString root = canonical(temporary.path());
        const QString missing = root + QStringLiteral("/missing");
        QVERIFY(!InstalledHelperStateDirectory::open(missing, geteuid(), &error));
        QVERIFY(!error.isEmpty());

        setPrivateMode(temporary.path());
        const QString nonCanonical = root + QStringLiteral("/.");
        QVERIFY(!InstalledHelperStateDirectory::open(nonCanonical, geteuid(), &error));
        QVERIFY(!error.isEmpty());
    }

    void rejectsSymlinkAndNonDirectory() {
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        setPrivateMode(temporary.path());

        const QString root = canonical(temporary.path());
        const QString linkPath = root + QStringLiteral("/link");
        const QByteArray linkBytes = QFile::encodeName(linkPath);
        const QByteArray targetBytes = QFile::encodeName(root);
        QCOMPARE(::symlink(targetBytes.constData(), linkBytes.constData()), 0);
        QString error;
        QVERIFY(!InstalledHelperStateDirectory::open(linkPath, geteuid(), &error));
        QVERIFY(!error.isEmpty());
        QVERIFY(::unlink(linkBytes.constData()) == 0);

        QTemporaryDir fileParent;
        QVERIFY(fileParent.isValid());
        const QString filePath = canonical(fileParent.path()) + QStringLiteral("/file");
        QFile file(filePath);
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.close();
        QVERIFY(!InstalledHelperStateDirectory::open(filePath, geteuid(), &error));
        QVERIFY(!error.isEmpty());
    }

    void rejectsSymlinkedParentSpelling() {
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        const QString root = canonical(temporary.path());
        const QString realParent = root + QStringLiteral("/real");
        QVERIFY(QDir().mkdir(realParent));
        const QString statePath = realParent + QStringLiteral("/state");
        QVERIFY(QDir().mkdir(statePath));
        setPrivateMode(statePath);

        const QString aliasParent = root + QStringLiteral("/alias");
        const QByteArray aliasBytes = QFile::encodeName(aliasParent);
        const QByteArray targetBytes = QFile::encodeName(realParent);
        QCOMPARE(::symlink(targetBytes.constData(), aliasBytes.constData()), 0);

        QString error;
        const QString aliasedStatePath = aliasParent + QStringLiteral("/state");
        QVERIFY(!InstalledHelperStateDirectory::open(aliasedStatePath, ownerOf(statePath), &error));
        QVERIFY(!error.isEmpty());
    }

    void rejectsWrongOwnerAndUnsafeModes() {
        QTemporaryDir wrongOwner;
        QVERIFY(wrongOwner.isValid());
        setPrivateMode(wrongOwner.path());
        const uid_t actualOwner = ownerOf(wrongOwner.path());
        const uid_t wrongExpectedOwner = actualOwner == 0 ? 1 : 0;
        QString error;
        const QString wrongOwnerPath = canonical(wrongOwner.path());
        QVERIFY(!InstalledHelperStateDirectory::open(wrongOwnerPath, wrongExpectedOwner, &error));
        QVERIFY(!error.isEmpty());

        QTemporaryDir unsafeMode;
        QVERIFY(unsafeMode.isValid());
        const QByteArray encoded = QFile::encodeName(unsafeMode.path());
        QCOMPARE(::chmod(encoded.constData(), 0750), 0);
        const QString unsafeModePath = canonical(unsafeMode.path());
        QVERIFY(
            !InstalledHelperStateDirectory::open(unsafeModePath, ownerOf(unsafeModePath), &error));
        QVERIFY(!error.isEmpty());
    }
};

QTEST_GUILESS_MAIN(M6InstalledHelperBootstrapTests)
#include "M6InstalledHelperBootstrapTests.moc"
