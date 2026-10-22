// Transport and Journal: the core's only outputs besides the EngineBridge.
#pragma once
#include <cstdint>
#include <string>
#include "re2net/core/messages.hpp"

namespace re2net::core {

// Outbound control. Messages addressed to the peer (ApplyMsg, ProgressMsg,
// HostDoneMsg, ResultMsg) must travel on the companion's reliable, ordered,
// non-coalescible lane; StatusMsg/CapsMsg are local to the companion.
// send() returns false on backpressure/overflow: the core then retires its current
// operation honestly instead of assuming delivery.
class Transport {
public:
    virtual ~Transport() = default;
    virtual bool send(const Message& m) = 0;
};

struct JournalRecord {
    uint64_t ms = 0;
    std::string connection;   // opaque connection token of the record's scope
    uint64_t op = 0;
    uint64_t req = 0;
    Role role = Role::None;
    std::string event;      // bounded identifier, e.g. "admitted", "invoke", "final"
    DoorPhase phase = DoorPhase::None;
    Reason reason = Reason::None;
    std::string detail;     // bounded free text (<= 120 chars), never pointers
};

class Journal {
public:
    virtual ~Journal() = default;
    virtual void write(const JournalRecord& r) = 0;
};

// One JSON line per record, for durable logs owned by the companion.
std::string journal_line(const JournalRecord& r);

}  // namespace re2net::core
