#pragma once

#include "HostSessionLease.hpp"
#include "NetworkSession.hpp"
#include "PfAnchorRecoveryCoordinator.hpp"

#include <optional>

namespace interceptor {

// Decorates an existing offline backend so session mutations require the host lease, and PF
// anchor changes go through the durable recovery coordinator. All methods must be called from
// the thread that constructs this object. The borrowed lease and collaborators must outlive it.
class PfAnchorRecoverySystemOperations final : public SystemOperations {
  public:
    PfAnchorRecoverySystemOperations(SystemOperations &delegate, const HostSessionLease &hostLease,
                                     PfAnchorRecoveryCoordinator &coordinator);

    std::optional<int> readSetting(NetworkSetting) override;
    SettingChange compareAndSetSetting(NetworkSetting, int expected, int desired) override;
    std::optional<QString> acquireSessionLease(const SessionSnapshot &) override;
    bool releaseSessionLease(const QString &) override;
    std::optional<QString> acquirePfReference() override;
    bool releasePfReference(const QString &token) override;
    bool installAnchor(const SessionSnapshot &) override;
    bool removeAnchor(const SessionSnapshot &) override;
    bool clearOwnedState(const SessionSnapshot &) override;
    bool beginArp(const SessionSnapshot &) override;
    bool endArp(const SessionSnapshot &) override;
    bool restoreNeighbors(const SessionSnapshot &) override;
    bool interfaceAvailable(const SessionSnapshot &) override;
    bool retainRecovery(const SessionSnapshot &, const OwnershipJournal &) override;

  private:
    bool ownerThread() const noexcept;
    bool activeSession() const noexcept;
    bool activeSession(const SessionSnapshot &) const noexcept;

    SystemOperations &delegate_;
    const HostSessionLease &hostLease_;
    PfAnchorRecoveryCoordinator &coordinator_;
    Qt::HANDLE ownerThreadId_;
    std::optional<QString> leaseToken_;
    std::optional<SessionSnapshot> sessionSnapshot_;
};

} // namespace interceptor
