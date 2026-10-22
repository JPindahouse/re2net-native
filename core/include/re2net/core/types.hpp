// re2net native co-op core: engine-independent value types.
// No REFramework, Lua or Windows types may appear in core headers.
#pragma once
#include <cstdint>
#include <string>

namespace re2net::core {

// A fact is either established (True/False) or not (Unknown). Unknown is never
// promoted to False or True by the core.
enum class Tri : uint8_t { Unknown = 0, False = 1, True = 2 };
const char* to_string(Tri t);
inline Tri tri(bool b) { return b ? Tri::True : Tri::False; }

enum class Role : uint8_t { None = 0, Host = 1, Guest = 2 };
const char* to_string(Role r);

// Which local actor performs the action. In the current mod the partner (guest
// player) is engine player 2 (HUNK) on both replicas; P1 is the host's Leon.
enum class ActorRole : uint8_t { P1 = 1, P2 = 2 };

// Engine GimmickDoorBase.SideType as read from the host door. Unknown is a
// diagnostic value only and can never be carried by an actionable command.
enum class Side : int8_t { Unknown = -1, A = 0, B = 1 };
const char* to_string(Side s);

// Identifier limits (characters). Connection and barrier identities are the
// companion's existing opaque canonical tokens (validated up to 128 characters);
// boot ids are native recorder ids (64). They are compared as exact strings only:
// never hashed, truncated or mapped to local counters.
constexpr size_t kMaxToken = 128;
constexpr size_t kMaxBoot = 64;
constexpr size_t kMaxDoorName = 64;
bool valid_token(const std::string& s, size_t max_len);   // [A-Za-z0-9_.:-]{1,max}

// Session scope. Every admitted operation is bound to exactly one Fence; any change
// of connection, barrier or boot retires it. The scene part may legitimately lag on
// the guest (it waits) or change after the partner crossed on the host.
struct Fence {
    std::string connection;    // role-ordered "<host_uuid>:<guest_uuid>" pair (73 chars), built by the companion
                               // from authenticated identities only (CONTRACT.md section 3); opaque here
    std::string barrier;       // accepted server state's shared barrier.id for the current scope (opaque)
    std::string host_boot;
    std::string guest_boot;
    uint32_t scene_location = 0;
    uint32_t scene_room = 0;
    bool operator==(const Fence&) const = default;
    bool same_scope_except_scene(const Fence& o) const {
        return connection == o.connection && barrier == o.barrier &&
               host_boot == o.host_boot && guest_boot == o.guest_boot;
    }
    bool same_scene(const Fence& o) const {
        return scene_location == o.scene_location && scene_room == o.scene_room;
    }
    bool valid() const {
        return valid_token(connection, kMaxToken) && valid_token(barrier, kMaxToken) &&
               valid_token(host_boot, kMaxBoot) && valid_token(guest_boot, kMaxBoot);
    }
};

// Prototype door identity: exact gimmick object name in an exact scene. A
// full-campaign authored identity still needs evidence; the core treats this as
// opaque equality only.
struct DoorKey {
    std::string name;          // e.g. "GasStation_ConvenienceDoor01A_gimmick"
    uint32_t location = 0;
    uint32_t room = 0;
    bool operator==(const DoorKey&) const = default;
};

// Fixed player-facing states (one per operation and peer view). Names state exactly
// what was observed: replica-door motion and actor crossing are separate facts.
enum class DoorPhase : uint8_t {
    None = 0,
    Opening,              // admitted, native write started, observing
    WaitingPartnerScene,  // guest has not yet reached the host's scene
    OpenBoth,             // BOTH replica doors showed swing progress
    OpenBothPartnerCrossedHost,  // ... and the partner actor (P2) changed door side on the HOST
                                 // replica. Not a claim that both players passed.
    Blocked,              // refused before any native write (reason says why)
    Interrupted,          // scope/actor/door changed after a native write started
    Uncertain,            // a write started but its result cannot be established
    Mismatch,             // one replica door moved, the other did not
};
const char* to_string(DoorPhase p);

// Why an operation ended the way it did. Stable wire strings.
enum class Reason : uint8_t {
    None = 0,
    NotPlaying, NoConsent, Disconnected, FenceChanged, SceneMismatch, SceneTimeout,
    DoorMissing, DoorDuplicate, DoorNotLoaded, DoorLocked, LockUnknown, AlreadyOpen,
    ActorMissing, HostFar, DistanceUnknown, Unsupported, NativeFalse, NativeException,
    NestedCall, Stale, Cancelled, Overflow, Duplicate, OutOfOrder, GuestTimeout,
    NoProgress, Busy, BadMessage, NotSelected, NoOpenMutation, InvalidOutbound,
    RoleChanged, ConsentLost,
    Count_  // sentinel, not a wire value
};
constexpr int kReasonCount = static_cast<int>(Reason::Count_);
const char* to_string(Reason r);

}  // namespace re2net::core
