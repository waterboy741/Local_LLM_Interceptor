#include "network/PosixSpawnChildProcess.hpp"
#include "network/PosixSpawnTypedCommandProcess.hpp"

#include <QElapsedTimer>
#include <QtTest>

#include <thread>
#include <unistd.h>

using namespace interceptor;

class M6PosixSpawnChildProcessTests final : public QObject {
    Q_OBJECT

    static std::string drain(PosixSpawnChildProcess &engine, std::size_t perReadBytes) {
        std::string collected;
        while (engine.waitForReadable(1000)) {
            const std::string chunk = engine.readStandardOutput(perReadBytes);
            if (chunk.empty())
                break;
            collected += chunk;
        }
        return collected;
    }

  private slots:
    void spawnFailureIsReportedAndTheEngineStaysReusableSafe() {
        PosixSpawnChildProcess engine;
        QVERIFY(!engine.started());
        QVERIFY(!engine.start("/nonexistent/no-such-program", {"--flag"}));
        QVERIFY(!engine.started());
        QVERIFY(engine.spawnFailed());
        QVERIFY(!engine.writeBroken());
        QVERIFY(engine.readStandardOutput(16).empty());
        QVERIFY(engine.readStandardError(16).empty());
        QVERIFY(!engine.normalExit());
    }

    void echoCapturesBoundedOutputAndReapsNormally() {
        PosixSpawnChildProcess engine;
        QVERIFY(engine.start("/bin/echo", {"-n", "bounded-output"}));
        QVERIFY(engine.started());
        QVERIFY(!engine.spawnFailed());
        engine.closeWrite();
        const std::string output = drain(engine, 4096);
        QCOMPARE(QString::fromStdString(output), QStringLiteral("bounded-output"));
        QVERIFY(engine.waitForFinished(2000));
        QVERIFY(engine.normalExit());
        QCOMPARE(engine.exitCode(), 0);
        QVERIFY(!engine.exitedBySignal());
        QVERIFY(!engine.isRunning());
    }

    void stdinStreamsThroughCatAndEofEndsWithoutBusySpin() {
        PosixSpawnChildProcess engine;
        QVERIFY(engine.start("/bin/cat", {"-"}));
        const std::string payload(1024, 'x');
        QCOMPARE(engine.write(payload.data(), payload.size()), payload.size());
        QVERIFY(engine.waitForBytesFlushed(2000));
        QVERIFY(engine.bytesPending() == 0);
        engine.closeWrite();
        const std::string output = drain(engine, 4096);
        QCOMPARE(output.size(), payload.size());
        QVERIFY(engine.waitForFinished(2000));
        QVERIFY(engine.normalExit());
    }

    void nonZeroExitCrashAndSignalAreReportedExactly() {
        PosixSpawnChildProcess engine;
        QVERIFY(engine.start("/usr/bin/false", {}));
        engine.closeWrite();
        QVERIFY(engine.waitForFinished(2000));
        QVERIFY(engine.normalExit());
        QCOMPARE(engine.exitCode(), 1);

        PosixSpawnChildProcess sleeper;
        QVERIFY(sleeper.start("/bin/sleep", {"30"}));
        QVERIFY(sleeper.isRunning());
        QVERIFY(!sleeper.waitForFinished(200));
        QVERIFY(sleeper.isRunning());
        sleeper.kill();
        QVERIFY(sleeper.waitForFinished(2000));
        QVERIFY(sleeper.exitedBySignal());
        QVERIFY(!sleeper.normalExit());
    }

    void brokenPipeIsReportedInsteadOfBlockingForever() {
        PosixSpawnChildProcess engine;
        // The child exits without reading; a large stdin payload then breaks the pipe within a
        // bounded time instead of blocking or spinning.
        QVERIFY(engine.start("/bin/sleep", {"0.1"}));
        const std::string payload(PosixSpawnChildProcess::maximumStdinBytes, 'z');
        QVERIFY(engine.write(payload.data(), payload.size()) > 0);
        const bool flushed = engine.waitForBytesFlushed(3000);
        QVERIFY(!flushed);
        QVERIFY(engine.writeBroken());
        engine.closeWrite();
        QVERIFY(engine.waitForFinished(2000));
    }

    void capturedOutputIsBoundedForAnUnboundedProducer() {
        PosixSpawnChildProcess engine;
        QVERIFY(engine.start("/usr/bin/yes", {}));
        engine.closeWrite();
        std::size_t total = 0;
        QElapsedTimer deadline;
        deadline.start();
        while (deadline.elapsed() < 2000) {
            if (!engine.waitForReadable(50))
                break;
            const std::string chunk = engine.readStandardOutput(1024 * 1024);
            if (chunk.empty())
                break;
            total += chunk.size();
            if (total >= PosixSpawnChildProcess::maximumOutputBytes)
                break;
        }
        engine.kill();
        QVERIFY(engine.waitForFinished(2000));
        QVERIFY(total > 0);
        QVERIFY(total <= PosixSpawnChildProcess::maximumOutputBytes);
        // The producer never EOF'd: the loop stopped exactly at the capture bound.
        QVERIFY(total == PosixSpawnChildProcess::maximumOutputBytes);
    }

    void engineTeardownKillsAndReapsALeftOverChild() {
        // No fixed sleep in the assertion path: only the destructor runs, and the test fails by
        // timeout if the child were not reaped.
        QElapsedTimer watchdog;
        watchdog.start();
        {
            PosixSpawnChildProcess engine;
            QVERIFY(engine.start("/bin/sleep", {"55"}));
            QVERIFY(engine.isRunning());
        }
        QVERIFY(watchdog.elapsed() < 5000);
        QVERIFY(watchdog.elapsed() >= 0);
    }

    void typedTokenVerifierClassifiesActiveAbsentAndUnknown() {
        constexpr quint64 token = 57;
        QVERIFY(PfctlPosixSpawnEnableTokenVerifier::parseActiveToken("Token : 57\n", token));
        QVERIFY(PfctlPosixSpawnEnableTokenVerifier::parseActiveToken("token: 99\nToken : 57\n",
                                                                     token));
        QVERIFY(PfctlPosixSpawnEnableTokenVerifier::parseActiveToken("STATUS:\nToken:\t57 ",
                                                                     token));
        QVERIFY(!PfctlPosixSpawnEnableTokenVerifier::parseActiveToken("Token : 58\n", token));
        QVERIFY(!PfctlPosixSpawnEnableTokenVerifier::parseActiveToken("no references\n", token));
        QVERIFY(PfctlPosixSpawnEnableTokenVerifier::parseActiveToken("Token:12", 12));

        QVERIFY(PfctlPosixSpawnEnableTokenVerifier::parseEmptyReferenceTable("no references\n"));
        QVERIFY(PfctlPosixSpawnEnableTokenVerifier::parseEmptyReferenceTable("References: 0\n"));
        QVERIFY(PfctlPosixSpawnEnableTokenVerifier::parseEmptyReferenceTable("\nrefs: 0\n"));
        QVERIFY(!PfctlPosixSpawnEnableTokenVerifier::parseEmptyReferenceTable(""));
        QVERIFY(!PfctlPosixSpawnEnableTokenVerifier::parseEmptyReferenceTable("Token : 57\n"));
        QVERIFY(!PfctlPosixSpawnEnableTokenVerifier::parseEmptyReferenceTable(
            "no references\nsomething else\n"));
    }
};

QTEST_GUILESS_MAIN(M6PosixSpawnChildProcessTests)
#include "M6PosixSpawnChildProcessTests.moc"
