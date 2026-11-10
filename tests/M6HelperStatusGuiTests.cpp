#include "gui/MainWindow.hpp"
#include "session/SessionController.hpp"

#include <QLabel>
#include <QPointer>
#include <QPushButton>
#include <QThread>
#include <QTimer>
#include <QtTest>

#include <atomic>

using namespace interceptor;

class M6HelperStatusGuiTests final : public QObject {
    Q_OBJECT

  private:
    void verifyMessage(XpcReadOnlyClientStatus resultStatus, const QString &expected) {
        SessionController controller;
        XpcReadOnlyClientResult result;
        result.status = resultStatus;
        result.service = QString(10000, QLatin1Char('x'));
        result.state = QString(10000, QLatin1Char('y'));
        MainWindow window(&controller, [result] { return result; });
        auto *button = window.findChild<QPushButton *>("checkHelperStatusButton");
        auto *status = window.findChild<QLabel *>("helperStatus");
        QVERIFY(button && status);
        button->click();
        QTRY_COMPARE_WITH_TIMEOUT(status->text(), expected, 2000);
        QVERIFY(button->isEnabled());
        QVERIFY(status->text().size() < 100);
    }

  private slots:
    void statusQueryRunsAsynchronouslyAndShowsBoundedSuccess() {
        SessionController controller;
        std::atomic_bool queryStarted = false;
        const auto guiThread = QThread::currentThread();
        MainWindow window(&controller, [&] {
            queryStarted.store(true);
            QThread::msleep(150);
            XpcReadOnlyClientResult result;
            result.status = XpcReadOnlyClientStatus::Success;
            result.ok = true;
            result.service = QString(10000, QLatin1Char('x'));
            result.state = QStringLiteral("inactive");
            result.protocolVersion = 1;
            return result;
        });

        auto *button = window.findChild<QPushButton *>("checkHelperStatusButton");
        auto *status = window.findChild<QLabel *>("helperStatus");
        QVERIFY(button && status);
        QCOMPARE(status->text(), QStringLiteral("Helper status not checked."));

        int timerTicks = 0;
        QTimer heartbeat(&window);
        heartbeat.setInterval(5);
        connect(&heartbeat, &QTimer::timeout, &window, [&] { ++timerTicks; });
        heartbeat.start();

        button->click();
        QVERIFY(!button->isEnabled());
        QCOMPARE(status->text(), QStringLiteral("Checking helper service…"));
        QTRY_VERIFY_WITH_TIMEOUT(queryStarted.load(), 1000);
        QTRY_COMPARE_WITH_TIMEOUT(
            status->text(), QStringLiteral("Helper available — state: inactive (protocol v1)."),
            2000);
        QVERIFY(timerTicks > 0);
        QVERIFY(button->isEnabled());
        QCOMPARE(QThread::currentThread(), guiThread);
    }

    void unavailableAndTimedOutResultsHaveFixedMessages() {
        verifyMessage(XpcReadOnlyClientStatus::ServiceUnavailable,
                      QStringLiteral("Helper unavailable — launchd service is not available."));
        verifyMessage(XpcReadOnlyClientStatus::TimedOut,
                      QStringLiteral("Helper status check timed out."));
    }

    void clearSessionIgnoresPendingResultAndResetsStatus() {
        SessionController controller;
        std::atomic_bool queryStarted = false;
        MainWindow window(&controller, [&] {
            queryStarted.store(true);
            QThread::msleep(250);
            XpcReadOnlyClientResult result;
            result.status = XpcReadOnlyClientStatus::Success;
            result.state = QStringLiteral("inactive");
            result.protocolVersion = 1;
            return result;
        });
        auto *button = window.findChild<QPushButton *>("checkHelperStatusButton");
        auto *clear = window.findChild<QPushButton *>("clearSessionButton");
        auto *status = window.findChild<QLabel *>("helperStatus");
        QVERIFY(button && clear && status);

        button->click();
        QTRY_VERIFY_WITH_TIMEOUT(queryStarted.load(), 1000);
        clear->click();
        QCOMPARE(status->text(), QStringLiteral("Helper status not checked."));
        QVERIFY(button->isEnabled());
        QTest::qWait(350);
        QCOMPARE(status->text(), QStringLiteral("Helper status not checked."));
    }

    void closingWindowDuringPendingQueryIsSafe() {
        std::atomic_bool queryFinished = false;
        auto *controller = new SessionController;
        auto *window = new MainWindow(controller, [&] {
            QThread::msleep(150);
            queryFinished.store(true);
            XpcReadOnlyClientResult result;
            result.status = XpcReadOnlyClientStatus::Success;
            result.state = QStringLiteral("inactive");
            result.protocolVersion = 1;
            return result;
        });
        controller->setParent(window);
        window->setAttribute(Qt::WA_DeleteOnClose);
        QPointer<MainWindow> guardedWindow(window);
        auto *button = window->findChild<QPushButton *>("checkHelperStatusButton");
        QVERIFY(button);
        button->click();
        window->close();
        QTRY_VERIFY_WITH_TIMEOUT(guardedWindow.isNull(), 1000);
        QTRY_VERIFY_WITH_TIMEOUT(queryFinished.load(), 2000);
        QTest::qWait(50);
    }
};

QTEST_MAIN(M6HelperStatusGuiTests)
#include "M6HelperStatusGuiTests.moc"
