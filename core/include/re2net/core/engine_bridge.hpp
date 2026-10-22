// EngineBridge: the only way the core touches the game. Implemented by a
// replaceable adapter (REFramework plugin first, standalone loader later) and by
// the offline FakeEngineBridge in tests.
//
// Threading contract: the core calls the bridge ONLY from DoorCore::tick(), and the
// adapter calls tick() ONLY from an engine callback on the game thread. References
// are opaque per-process tokens: the adapter re-resolves and validates (token,
// incarnation) on every call and returns Stale instead of touching a replaced or
// destroyed object. No managed reference is kept across callbacks.
#pragma once
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include "re2net/core/types.hpp"

namespace re2net::core {

struct ObjRef {
    uint64_t token = 0;        // adapter-local handle kind, never sent on the wire
    uint64_t incarnation = 0;  // identity of the underlying object at resolution time
    bool valid() const { return token != 0; }
    bool operator==(const ObjRef&) const = default;
};

enum class LookupStatus : uint8_t { Found, Missing, Duplicate, NotLoaded, Unsupported, Error };

struct Lookup {
    LookupStatus status = LookupStatus::Error;
    ObjRef ref{};
};

// Stale/Unsupported/NestedRefused/PermitDenied: the adapter guarantees it did NOT call
// the engine. ReturnedTrue/ReturnedFalse/Exception: the engine method was entered (a
// write may have started, even when it returned false or threw).
enum class InvokeStatus : uint8_t {
    ReturnedTrue, ReturnedFalse, Exception, Stale, Unsupported, NestedRefused,
    PermitDenied   // R1414 static review: the caller's permit failed after the adapter's last reads
};

// The caller's authority, evaluated by the adapter AFTER its own final engine reads and
// immediately before the mutating call (R1414 static review finding 1). Must be pure
// state (no engine or bridge calls) and must not re-enter the bridge. A check cannot
// cancel an engine call that has already been entered.
using Permit = std::function<bool()>;
inline bool engine_entered(InvokeStatus s) {
    return s == InvokeStatus::ReturnedTrue || s == InvokeStatus::ReturnedFalse ||
           s == InvokeStatus::Exception;
}

struct InvokeResult {
    InvokeStatus status = InvokeStatus::Unsupported;
    // The REQUESTED door's onOpened was entered (pre-hook, matching receiver, this
    // thread, this invocation) synchronously inside this call. Entry only: it does not
    // prove the original body ran, since another hook may skip it. A no-pair/early branch
    // may return true WITHOUT it. Unknown when the witness is unavailable or a hook
    // event could not be attributed.
    Tri on_opened = Tri::Unknown;
    // The acting actor's position changed by more than the adapter's threshold inside
    // the call (e.g. pair/Jack interpolation). Unknown when positions are unreadable.
    Tri actor_displaced = Tri::Unknown;
};

// One post-update observation of the door's own engine state. Every field may be
// unreadable; `readable` false means nothing below is meaningful.
struct DoorSample {
    bool readable = false;
    Tri opened = Tri::Unknown;     // get_IsOpened: nullable opened side present (logical, not physical)
    Side opened_side = Side::Unknown;
    Tri locked = Tri::Unknown;     // get_IsLocked
    // PeekedWork progress for the opened side, RAW engine units. The core never
    // assumes a 0..1 normalization; it only measures change.
    std::optional<float> value;
    // The PeekedWork side `value` was read from. A value is only compared with a
    // baseline of the same side; an adapter never substitutes another side's work.
    Side value_side = Side::Unknown;
    std::optional<float> speed;
    std::optional<int32_t> routine;     // _PeekedRno
    Tri motion_layer = Tri::Unknown;    // PeekedWork.MotionLayer present
    uint64_t update_seq = 0;            // advances once per observed engine update
};

enum class FollowStatus : uint8_t { Applied, NotOpen, Stale, Unsupported, Exception };

// Door-scoped co-op eligibility.
// The engine's own per-frame door simulation chooses its pusher and its hold-open
// contact from GimmickDoorBase.collectPlCharactors() = [CurrentPlayer, NPC PL2000,
// NPC PL3000]; the co-op partner (PL4000) is in neither. While a lease is held, the
// adapter lets exactly the leased door's own updatePeeked/updateCount see the leased
// actor in an EMPTY NPC slot of that freshly collected list. CurrentPlayer and real
// NPC entries are never replaced; every other door and call is untouched. The leaf
// animation, collider modes, endpoints and closing remain the engine's own.
struct EligibilityReport {
    bool active = false;          // a lease is currently held
    uint32_t scopes = 0;          // leased-door update scopes entered since the lease began
    uint32_t injected = 0;        // collected lists that received the actor
    uint32_t already_member = 0;  // lists that already contained the actor (nothing changed)
    uint32_t no_free_slot = 0;    // lists with no empty NPC slot (nothing changed)
    uint32_t refused = 0;         // lists not changed for safety (unreadable, setter failed)
    uint32_t unbalanced = 0;      // scope stacks found unbalanced at a frame start (reset)
    uint32_t revoked_in_hook = 0; // leases the hook itself released (live/identity/permit/fault)
    uint32_t hook_faults = 0;     // C++ exceptions contained at the hook boundary
    uint32_t reentry_refused = 0; // nested injection attempts refused
    uint32_t foreign_thread_refused = 0;  // lease API calls refused off the engine owner thread (R1446)
};

struct EngineCaps {
    bool build_ok = false;          // exact reviewed game executable admitted (digest gate) AND contracts resolved
    bool api_ok = false;            // loader/plugin API version acceptable
    bool door_types_ok = false;     // door types/methods/fields resolved with exact signatures
    bool actor_open_ok = false;     // host actor-explicit open backend available
    bool mirror_open_ok = false;    // guest mirror backend available
    bool follow_ok = false;         // guest leaf-follow backend available (off until grounded)
    bool witness_ok = false;        // onOpened witness hook installed
    std::string detail;             // bounded, human-readable
    bool eligibility_ok = false;    // door-scoped co-op eligibility lease available
};

class EngineBridge {
public:
    virtual ~EngineBridge() = default;
    virtual EngineCaps caps() const = 0;

    // Unique current local door for the key; Duplicate/Missing/NotLoaded are never
    // collapsed into Found.
    virtual Lookup resolve_door(const DoorKey& key) = 0;
    virtual Lookup resolve_actor(ActorRole who) = 0;
    virtual bool still_valid(ObjRef ref) = 0;

    // Horizontal (XZ) distance actor -> door center, the existing 8 m guard measure.
    virtual std::optional<float> distance(ObjRef actor, ObjRef door) = 0;
    // Engine door side of the actor's position; Unknown when not grounded.
    virtual Side actor_side(ObjRef actor, ObjRef door) = 0;

    // Host: actor-explicit native open. Never swaps global CurrentPlayer/CurrentInventory.
    // `permit` is checked after the adapter's final reads, right before the invoke.
    virtual InvokeResult open_by_actor(ObjRef door, ObjRef actor, const Permit& permit) = 0;
    // Guest: open the local replica door with the local replica of the same acting actor.
    // `side` is the host's opened side. The current adapter does NOT force or compare it
    // (the engine derives the side from the actor position); no direction or leaf
    // equivalence between replicas is established (R1414 static review finding 5).
    virtual InvokeResult open_mirror(ObjRef door, ObjRef actor, Side side, const Permit& permit) = 0;
    // Guest: drive the local leaf toward the host's sampled raw value (only when
    // caps().follow_ok; the scale mapping must be grounded first).
    virtual FollowStatus follow(ObjRef door, float target_value) = 0;

    virtual DoorSample sample(ObjRef door) = 0;

    // Grant or renew the eligibility lease for exactly (door, actor). False: unsupported,
    // stale or refused, and no lease is held. Only one lease exists at a time.
    // Engine owner thread only: a call from any other thread is refused before any lease
    // state is read, and never releases or changes the owner's lease (R1446 review).
    virtual bool lease_eligibility(ObjRef /*door*/, ObjRef /*actor*/) { return false; }
    // Ends any lease. State-only and non-throwing: safe from every retirement path,
    // including inside receive() and the core's exception handler. Owner thread only;
    // elsewhere it is a counted no-op (cleanup stays owner-thread work).
    // The adapter's hook may also end the lease by itself between ticks; eligibility()
    // .active then reads false and the core reconciles (it never assumes a held lease).
    virtual void release_eligibility() noexcept {}
    virtual EligibilityReport eligibility() const { return {}; }
};

}  // namespace re2net::core
