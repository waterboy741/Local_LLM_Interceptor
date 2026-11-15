#include "network/HelperIdentity.hpp"

#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QTemporaryDir>
#include <QtTest>

#include <cstdlib>
#include <memory>
#include <sys/stat.h>
#include <unistd.h>

using namespace interceptor;

namespace {

const QByteArray requirement = "cdhash H\"0123456789abcdef0123456789abcdef01234567\"";
const QByteArray identity = "helper-code-requirement=" + requirement;

QByteArray canonicalPath(const QString &path) {
    const std::unique_ptr<char, decltype(&std::free)> resolved(
        ::realpath(QFile::encodeName(path).constData(), nullptr), &std::free);
    return resolved ? QByteArray(resolved.get()) : QByteArray{};
}

class IdentityFixture {
  public:
    const QTemporaryDir directory;
    const QByteArray parent = canonicalPath(directory.path());
    const QByteArray path = parent + "/helper.identity";

    bool write(const QByteArray &content) const {
        QFile file(QFile::decodeName(path));
        return file.open(QIODevice::WriteOnly | QIODevice::Truncate) &&
               file.write(content) == content.size() && file.flush() &&
               chmod(path.constData(), 0644) == 0;
    }
};

} // namespace

class M6HelperIdentityTests final : public QObject {
    Q_OBJECT

  private slots:
    void loadsExactCdHashWithOptionalFinalNewline() {
        const IdentityFixture fixture;
        QVERIFY(fixture.directory.isValid() && !fixture.parent.isEmpty());

        for (const auto &content : {identity, identity + '\n'}) {
            QVERIFY(fixture.write(content));
            const auto result = loadHelperIdentity(fixture.path, geteuid());
            QCOMPARE(result.status, HelperIdentityStatus::Loaded);
            QCOMPARE(result.requirement, requirement);
        }
    }

    void rejectsInvalidContent_data() {
        QTest::addColumn<QByteArray>("content");
        QTest::newRow("empty") << QByteArray{};
        QTest::newRow("unknown-field") << ("requirement=" + requirement);
        QTest::newRow("short-cdhash") << QByteArray{"helper-code-requirement=cdhash H\"0123\""};
        auto longContent = identity;
        longContent.insert(longContent.size() - 1, 'a');
        QTest::newRow("long-cdhash") << longContent;
        auto nonHexContent = identity;
        nonHexContent[nonHexContent.size() - 2] = 'z';
        QTest::newRow("nonhex-cdhash") << nonHexContent;
        QTest::newRow("identifier-only")
            << QByteArray{"helper-code-requirement=identifier \"org.example.helper\""};
        QTest::newRow("broadened-requirement") << (identity + " or always");
        QTest::newRow("duplicate-field") << (identity + '\n' + identity + '\n');
        QTest::newRow("multiple-lines") << (identity + "\n\n");
        auto nulContent = identity;
        nulContent[nulContent.size() - 2] = '\0';
        QTest::newRow("embedded-nul") << nulContent;
        QTest::newRow("trailing-nul") << (identity + QByteArray(1, '\0'));
        QTest::newRow("oversized") << (identity + QByteArray(65536, ' '));
    }

    void rejectsInvalidContent() {
        QFETCH(QByteArray, content);
        const IdentityFixture fixture;
        QVERIFY(fixture.directory.isValid() && !fixture.parent.isEmpty());
        QVERIFY(fixture.write(content));
        const auto result = loadHelperIdentity(fixture.path, geteuid());
        QCOMPARE(result.status, HelperIdentityStatus::Invalid);
        QVERIFY(result.requirement.isEmpty());
    }

    void distinguishesMissingFromInvalid() {
        const IdentityFixture fixture;
        QVERIFY(fixture.directory.isValid() && !fixture.parent.isEmpty());

        for (const auto &path : {fixture.path, fixture.parent + "/missing/helper.identity"}) {
            const auto result = loadHelperIdentity(path, geteuid());
            QCOMPARE(result.status, HelperIdentityStatus::Missing);
            QVERIFY(result.requirement.isEmpty());
        }
    }

    void rejectsUnexpectedOwnerAndWritableModes() {
        const IdentityFixture fixture;
        QVERIFY(fixture.directory.isValid() && !fixture.parent.isEmpty());
        QVERIFY(fixture.write(identity));

        const uid_t owner = geteuid();
        const uid_t differentOwner = owner == 0 ? 1 : 0;
        QCOMPARE(loadHelperIdentity(fixture.path, differentOwner).status,
                 HelperIdentityStatus::Invalid);

        QVERIFY(chmod(fixture.path.constData(), 0664) == 0);
        QCOMPARE(loadHelperIdentity(fixture.path, owner).status, HelperIdentityStatus::Invalid);
        QVERIFY(chmod(fixture.path.constData(), 0644) == 0);
        QVERIFY(chmod(fixture.parent.constData(), 0777) == 0);
        QCOMPARE(loadHelperIdentity(fixture.path, owner).status, HelperIdentityStatus::Invalid);
    }

#ifdef Q_OS_MACOS
    void rejectsExtendedAcl() {
        const IdentityFixture fixture;
        QVERIFY(fixture.directory.isValid() && !fixture.parent.isEmpty());
        QVERIFY(fixture.write(identity));

        const auto path = QFile::decodeName(fixture.path);
        QCOMPARE(QProcess::execute("/bin/chmod", {"+a", "everyone allow write", path}), 0);
        QCOMPARE(loadHelperIdentity(fixture.path, geteuid()).status, HelperIdentityStatus::Invalid);
        QCOMPARE(QProcess::execute("/bin/chmod", {"-N", path}), 0);
        QCOMPARE(loadHelperIdentity(fixture.path, geteuid()).status, HelperIdentityStatus::Loaded);
    }
#endif

    void rejectsSymlinkFileAndParent() {
        const IdentityFixture fixture;
        QVERIFY(fixture.directory.isValid() && !fixture.parent.isEmpty());
        QVERIFY(fixture.write(identity));

        const auto fileLink = fixture.parent + "/identity-link";
        QVERIFY(symlink(fixture.path.constData(), fileLink.constData()) == 0);
        QCOMPARE(loadHelperIdentity(fileLink, geteuid()).status, HelperIdentityStatus::Invalid);

        const IdentityFixture other;
        QVERIFY(other.directory.isValid() && !other.parent.isEmpty());
        const auto parentLink = other.parent + "/linked-parent";
        QVERIFY(symlink(fixture.parent.constData(), parentLink.constData()) == 0);
        QCOMPARE(loadHelperIdentity(parentLink + "/helper.identity", geteuid()).status,
                 HelperIdentityStatus::Invalid);
    }

    void rejectsIntermediateDirectorySymlink() {
        const IdentityFixture fixture;
        QVERIFY(fixture.directory.isValid() && !fixture.parent.isEmpty());
        QVERIFY(fixture.write(identity));

        const IdentityFixture other;
        QVERIFY(other.directory.isValid() && !other.parent.isEmpty());
        const QFileInfo parentInfo(QFile::decodeName(fixture.parent));
        const auto ancestorLink = other.parent + "/linked-ancestor";
        QVERIFY(symlink(QFile::encodeName(parentInfo.path()).constData(),
                        ancestorLink.constData()) == 0);
        const auto linkedPath =
            ancestorLink + '/' + QFile::encodeName(parentInfo.fileName()) + "/helper.identity";
        QCOMPARE(loadHelperIdentity(linkedPath, geteuid()).status, HelperIdentityStatus::Invalid);
    }

    void sendsStatusOnlyWithLoadedIdentity() {
        const IdentityFixture fixture;
        QVERIFY(fixture.directory.isValid() && !fixture.parent.isEmpty());
        QList<QByteArray> requests;
        const auto trustedRequest = [&requests](const QByteArray &peerRequirement) {
            requests.append(peerRequirement);
            XpcReadOnlyClientResult result;
            result.status = XpcReadOnlyClientStatus::Success;
            result.ok = true;
            return result;
        };
        const auto query = [&] {
            return queryTrustedHelperStatus(loadHelperIdentity(fixture.path, geteuid()),
                                            trustedRequest);
        };

        QCOMPARE(query().status, XpcReadOnlyClientStatus::HelperIdentityMissing);
        QVERIFY(requests.isEmpty());
        QVERIFY(fixture.write("helper-code-requirement=always"));
        QCOMPARE(query().status, XpcReadOnlyClientStatus::HelperIdentityInvalid);
        QVERIFY(requests.isEmpty());
        QVERIFY(fixture.write(identity));
        QCOMPARE(query().status, XpcReadOnlyClientStatus::Success);
        QCOMPARE(requests, QList<QByteArray>{requirement});
    }

    void rejectsDirectoryAndFifoAsIdentity() {
        const IdentityFixture fixture;
        QVERIFY(fixture.directory.isValid() && !fixture.parent.isEmpty());
        QVERIFY(mkdir(fixture.path.constData(), 0755) == 0);
        QCOMPARE(loadHelperIdentity(fixture.path, geteuid()).status, HelperIdentityStatus::Invalid);
        QVERIFY(rmdir(fixture.path.constData()) == 0);
        QVERIFY(mkfifo(fixture.path.constData(), 0600) == 0);
        QCOMPARE(loadHelperIdentity(fixture.path, geteuid()).status, HelperIdentityStatus::Invalid);
    }
};

QTEST_APPLESS_MAIN(M6HelperIdentityTests)
#include "M6HelperIdentityTests.moc"
