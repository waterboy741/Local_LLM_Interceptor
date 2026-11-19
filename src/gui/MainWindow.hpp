#pragma once
#include "network/XpcReadOnlyServiceClient.hpp"
#include "network/XpcSessionControlClient.hpp"
#include "proxy/ProxyServer.hpp"
#include "session/SessionController.hpp"
#include <QMainWindow>
#include <functional>
class QLineEdit;
class QComboBox;
class QSpinBox;
class QLabel;
class QListWidget;
class QTextEdit;
class QTimer;
class QPushButton;
namespace interceptor {
class MainWindow : public QMainWindow {
    Q_OBJECT
  public:
    explicit MainWindow(SessionController *controller, QWidget *parent = nullptr);
    MainWindow(SessionController *controller,
               std::function<XpcReadOnlyClientResult()> helperStatusRequest,
               QWidget *parent = nullptr);

  protected:
    void closeEvent(QCloseEvent *event) override;

  private:
    // Transparent session-control wiring. The heartbeat timer ticks on the GUI thread but
    // every XPC request runs off the GUI thread; stale replies are dropped by generation.
    void beginStartTransparentSession();
    void beginStopTransparentSession(bool blocking);
    void handleStopReply(const XpcSessionControlClientResult &result);
    void finishTransparentSession();

    SessionController *controller_;
    QComboBox *interface_;
    QLineEdit *client_, *server_, *paths_;
    QSpinBox *port_;
    QLabel *status_;
    ProxyServer proxy_;
    QSpinBox *listenPort_;
    QListWidget *requests_;
    QTextEdit *details_;
    QListWidget *messageItems_;
    QTextEdit *messageDetails_;
    quint64 helperStatusGeneration_ = 0;
    QTimer *transparentHeartbeatTimer_ = nullptr;
    quint64 transparentRequestGeneration_ = 0;
    QString transparentSessionId_;
    QByteArray transparentSessionCapability_;
    QLabel *transparentSessionStatus_ = nullptr;
    QPushButton *transparentSessionStart_ = nullptr;
    QPushButton *transparentSessionStop_ = nullptr;
    QPushButton *explicitProxyStart_ = nullptr;
    bool transparentHeartbeatInFlight_ = false;
};
} // namespace interceptor
