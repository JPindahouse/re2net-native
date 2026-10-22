// Typed, strictly bounded control messages: contract re2net.door v1 (see CONTRACT.md).
//
// Every message is one flat JSON object of at most kMaxMessageBytes with a fixed key
// set: unknown keys, missing keys, wrong types, out-of-range integers or invalid
// identifiers are rejected on decode AND on encode (encode never normalizes an
// invalid enum, side, actor or fence into an actionable value). Every peer control
// message carries the complete Fence so it can only resolve against one exact
// current operation. All door control is reliable, ordered and non-coalescible; it
// must not ride the fast pose lane. Sender role/connection are authenticated by the
// companion/server, never taken from a payload.
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include "re2net/core/types.hpp"

namespace re2net::core {

constexpr size_t kMaxMessageBytes = 1024;
constexpr const char* kDoorImpl = "door.native.v1";
constexpr uint32_t kMaxValueMilli = 1000000;   // |raw engine value| <= 1000.0 on the wire

// Raw engine swing value carried losslessly enough for diagnostics and following,
// WITHOUT assuming a 0..1 normalization: magnitude in thousandths plus sign.
struct WireValue {
    uint32_t milli = 0;
    bool negative = false;
    static std::optional<WireValue> from(float v);   // nullopt if non-finite or out of range
    float to_float() const { return (negative ? -1.0f : 1.0f) * static_cast<float>(milli) / 1000.0f; }
    bool operator==(const WireValue&) const = default;
};

// --- companion -> local core -------------------------------------------------
struct SessionMsg {          // t="session": authoritative local session view
    Fence fence;
    Role role = Role::None;
    bool connected = false;
    bool consent = false;    // fresh explicit Ready on both peers for this fence
    bool playing = false;    // both prepared/playing in the same scene
};
struct IntentMsg {           // t="door_intent" (host only): partner interact at a door
    Fence fence;
    uint64_t req = 0;        // monotonic per fence (connection+barrier)
    DoorKey door;
    ActorRole actor = ActorRole::P2;
};
struct CancelMsg {           // t="door_cancel": user/leave cancellation
    Fence fence;
    uint64_t op = 0;
};

// --- peer <-> peer (via the companion's reliable ordered lane) ---------------
struct SelectMsg {           // t="door_select" host->guest: propose kDoorImpl for this fence
    Fence fence;
    std::string impl;
};
struct SelectAckMsg {        // t="door_select_ack" guest->host
    Fence fence;
    std::string impl;
    bool ok = false;
    Reason reason = Reason::None;
};
struct ApplyMsg {            // t="door_apply": host-authorized open for the guest
    Fence fence;
    uint64_t op = 0;         // host-monotonic per fence
    uint64_t req = 0;
    DoorKey door;
    Side side = Side::Unknown;   // must be A or B on the wire
};
struct ProgressMsg {         // t="door_progress": host swing samples, bounded count
    Fence fence;
    uint64_t op = 0;
    uint32_t n = 0;          // sample index, strictly increasing per op, <= 1000
    WireValue value;         // raw host PeekedWork.Value of the opened side
};
struct HostDoneMsg {         // t="door_host_done": host local outcome is final
    Fence fence;
    uint64_t op = 0;
    Tri progress = Tri::Unknown;
    Tri crossed = Tri::Unknown;  // partner actor changed side on the host replica
    Reason reason = Reason::None;
};
struct ResultMsg {           // t="door_result": guest local outcome (final)
    Fence fence;
    uint64_t op = 0;
    DoorPhase phase = DoorPhase::None;
    Reason reason = Reason::None;
    Tri opened = Tri::Unknown;   // nullable opened side present (NOT a physical-open predicate)
    Tri progress = Tri::Unknown;
};

// --- local core -> companion (status/UI/log) ---------------------------------
struct StatusMsg {           // t="door_status"
    Fence fence;
    uint64_t op = 0;
    uint64_t req = 0;
    Role role = Role::None;
    DoorPhase phase = DoorPhase::None;
    Reason reason = Reason::None;
};
struct CapsMsg {             // t="caps": what this peer can run
    bool ok = false;
    uint32_t core_version = 1;
    std::string impl;        // kDoorImpl when ok, else "none"
};

using Message = std::variant<SessionMsg, IntentMsg, CancelMsg, SelectMsg, SelectAckMsg, ApplyMsg,
                             ProgressMsg, HostDoneMsg, ResultMsg, StatusMsg, CapsMsg>;

// Strict encode: nullopt (with a bounded reason) when the message violates the
// contract, e.g. Side::Unknown in an actionable command, an invalid fence/token,
// an unknown enum value or a result larger than kMaxMessageBytes.
std::optional<std::string> encode(const Message& m, std::string* error = nullptr);
std::optional<Message> decode(std::string_view text, std::string* error = nullptr);
const char* type_name(const Message& m);
bool is_peer_message(const Message& m);

}  // namespace re2net::core
