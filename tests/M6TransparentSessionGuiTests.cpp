#include "gui/MainWindow.hpp"
#include "network/HelperIdentity.hpp"
#include "session/SessionController.hpp"

#include <QApplication>
#include <QLabel>
#include <QNetworkInterface>
#include <QPushButton>
#include <QTabWidget>
#include <QTimer>
#include <QtTest>

#include <optional>

using namespace interceptor;

namespace {
std::optional<QString> activeNonLoopbackInterface() {
    for (const QNetworkInterface &entry : QNetworkInterface::allInterfaces()) {
        const auto flags = entry.flags();
        if (!flags.testFlag(QNetworkInterface::IsUp) ||
            !flags.testFlag(QNetworkInterface::IsRunning) ||
            flags.testFlag(QNetworkInterface::IsLoopBack))
            continue;
        for (const QNetworkAddressEntry &address : entry.addressEntries())
            if (address.ip().protocol() == QAbstractSocket::IPv4Protocol)
                return entry.name();
    }
    return std::nullopt;
}

SessionConfig demoConfig(const QString &interfaceName) {
    return {interfaceName, "192.0.2.10", "192.0.2.30", 18081, {"/api/generate", "/api/chat"},
            false};
}
} // namespace

class M6TransparentSessionGuiTests final : public QObject {
    Q_OBJECT

  private slots:
    void transparentTabIsLastAndTheEarlierTabsAreUnchanged() {
        SessionController controller;
        MainWindow window(&controller, [] {
            XpcReadOnlyClientResult result;
            result.status = XpcReadOnlyClientStatus::ServiceUnavailable;
            return result;
        });
        auto *tabs = window.findChild<QTabWidget *>();
        QVERIFY(tabs != nullptr);
        QCOMPARE(tabs->count(), 5);
        const QList<QString> expected = {QStringLiteral("Configuration"), QStringLiteral("Requests"),
                                         QStringLiteral("Modify settings"),
                                         QStringLiteral("Held requests"),
                                         QStringLiteral("Transparent session")};
        for (int index = 0; index < tabs->count(); ++index)
            QCOMPARE(tabs->tabText(index), expected.at(index));
        auto *status = window.findChild<QLabel *>(QStringLiteral("transparentSessionStatus"));
        QVERIFY(status != nullptr);
        QCOMPARE(status->text(), QStringLiteral("No transparent session."));

        // The Stop action of a not-yet-started session stays disabled, and no heartbeat loop
        // is running.
        auto *stop = window.findChild<QPushButton *>(QStringLiteral("stopTransparentButton"));
        QVERIFY(stop != nullptr);
        QVERIFY(!stop->isEnabled());
        auto *timer = window.findChild<QTimer *>(QStringLiteral("transparentHeartbeatTimer"));
        QVERIFY(timer != nullptr);
        QVERIFY(!timer->isActive());
    }

    void startRequiresAPreparedConfiguration() {
        SessionController controller;
        MainWindow window(&controller, [] {
            XpcReadOnlyClientResult result;
            result.status = XpcReadOnlyClientStatus::ServiceUnavailable;
            return result;
        });
        auto *start = window.findChild<QPushButton *>(QStringLiteral("startTransparentButton"));
        auto *status = window.findChild<QLabel *>(QStringLiteral("transparentSessionStatus"));
        QVERIFY(start && status);

        // Nothing prepared yet.
        start->click();
        QCOMPARE(status->text(),
                 QStringLiteral("Prepare an interface configuration first; the transparent "
                                "session reuses it."));
        QVERIFY(start->isEnabled());

        // A loopback-only observation cannot back a redirect session.
        QVERIFY(controller.prepare(demoConfig(QStringLiteral("lo0"))));
        start->click();
        const QString inactiveText = status->text();
        QVERIFY(inactiveText == QStringLiteral("The selected interface is inactive or has no "
                                               "usable IPv4 address.") ||
                 inactiveText == QStringLiteral("Transparent sessions need a selected physical "
                                                "interface; loopback-only explicit "
                                                "configurations cannot redirect."));
        QVERIFY(start->isEnabled());
    }

    void startFailsClosedWhenTheHelperIdentityIsNotConfiguredOffline() {
        const auto interfaceName = activeNonLoopbackInterface();
        if (!interfaceName)
            QSKIP("An active non-loopback IPv4 interface is required for the offline start flow.");
        const HelperIdentity identity = loadHelperIdentity();
        if (identity.status == HelperIdentityStatus::Loaded)
            QSKIP("A helper identity is installed on this machine; skip to avoid a live call.");

        SessionController controller;
        QVERIFY(controller.prepare(demoConfig(*interfaceName)));
        MainWindow window(&controller, [] {
            XpcReadOnlyClientResult result;
            result.status = XpcReadOnlyClientStatus::ServiceUnavailable;
            return result;
        });
        auto *start = window.findChild<QPushButton *>(QStringLiteral("startTransparentButton"));
        auto *stop = window.findChild<QPushButton *>(QStringLiteral("stopTransparentButton"));
        auto *status = window.findChild<QLabel *>(QStringLiteral("transparentSessionStatus"));
        auto *timer = window.findChild<QTimer *>(QStringLiteral("transparentHeartbeatTimer"));
        QVERIFY(start && stop && status && timer);

        // Deterministic, bounded transition: the synchronous offline guard reports before any
        // helper call and the action stays available for a retry.
        start->click();
        QCOMPARE(status->text(),
                 QStringLiteral("Helper identity is not configured; transparent start fails "
                                 "closed."));
        QVERIFY(start->isEnabled());
        QVERIFY(!stop->isEnabled());
        QVERIFY(!timer->isActive());
        // The transparent listener stays owned by the GUI (no session handle exists).
        auto *sessionIdLabel = status;
        QVERIFY(!sessionIdLabel->text().contains(QStringLiteral("Session")));
        window.close();
    }

    void closeWithoutASessionStopsQuietly() {
        SessionController controller;
        MainWindow window(&controller, [] {
            XpcReadOnlyClientResult result;
            result.status = XpcReadOnlyClientStatus::ServiceUnavailable;
            return result;
        });
        // A guard that dismisses any unexpected modal dialog (the close path would only show
        // one when a transparent session were active).
        QTimer::singleShot(0, &window, [&window] {
            for (QWidget *modal : QApplication::topLevelWidgets())
                if (modal->isModal())
                    modal->close();
            window.close();
        });
        window.show();
        window.close();
        QVERIFY(!window.isVisible());
    }
};

QTEST_MAIN(M6TransparentSessionGuiTests)
#include "M6TransparentSessionGuiTests.moc"
