#pragma once

#include "ArpLabProbeRunner.hpp"
#include "MacBpfArpPacketIo.hpp"

#include <QList>
#include <QString>
#include <QStringList>

namespace interceptor {

struct ArpProbeAddressEntry {
    QString ipv4;
    int prefixLength = 0;
};

struct ArpProbeInterfaceEvidence {
    bool found = false;
    bool up = false;
    bool running = false;
    QString interfaceName;
    QString macAddress;
    QList<ArpProbeAddressEntry> ipv4Addresses;
};

class ArpProbeInterfaceInspector {
  public:
    virtual ~ArpProbeInterfaceInspector() = default;
    virtual ArpProbeInterfaceEvidence inspect(const QString &interfaceName) = 0;
};

struct ArpLabProbeCliResult {
    int exitCode = 2;
    QString standardOutput;
    QString standardError;
};

class ArpLabProbeCli {
  public:
    static ArpLabProbeCliResult run(const QStringList &arguments);
    static ArpLabProbeCliResult run(const QStringList &arguments, BpfSystemCalls &systemCalls,
                                    ArpProbeWaiter &waiter,
                                    ArpProbeInterfaceInspector &interfaceInspector);
};

} // namespace interceptor
