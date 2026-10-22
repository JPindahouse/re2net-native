// ReEngineBridge: core::EngineBridge over REFramework's checked C plugin API
// (reframework/API.h, plugin API 1.15.0, pinned c4b1314). Replaceable adapter.
//
// Rules:
//  - Exact-build gate: build_ok requires the plugin's executable digest gate (the
//    reviewed re2.exe SHA-256, checked in plugin initialize) AND every contract below.
//  - Exact contracts: every type/method/field is resolved by name AND its return type,
//    parameter types and staticness are verified. Preflight uses TDB metadata only (enum
//    underlying type via the `value__` field, never managed reflection).
//  - Only the checked `method->invoke` path is used (REFrameworkResult + exception flag
//    checked separately). Arguments are managed-object pointers, 8-byte integers, or
//    (calcSide only) ONE pointer slot to an aligned 16-byte via.vec3 block on the
//    calling frame. No raw function address or guessed native ABI.
//  - Enumeration never claims uniqueness it did not establish: an array longer than the
//    scan bound is Unsupported, and every index (nulls included) counts toward the bound.
//  - No managed reference is kept across callbacks. ObjRef.incarnation is an adapter-
//    issued serial bound to (object address, current scene object); every call
//    re-resolves on the engine callback and requires the same address in the same
//    scene. Same-address reuse inside one scene remains a known limit.
//  - onOpened witness: bound to the requested receiver, this thread and this invocation.
//    Pre-hook entry only (another hook may skip the body).
//  - Calls only from the engine callback thread that drives DoorCore::tick(); engine
//    mutations are not re-entrant (NestedRefused). The owner thread is published
//    atomically and checked before any mutable state is read (R1414 static review).
//  - Every mutation re-checks the caller's Permit after the adapter's last managed reads,
//    immediately before the invoke (PermitDenied = not entered). The eligibility hook
//    re-checks the partner's current native identity AFTER its array reads, then the
//    pure hook permit for the exact leased refs, with no managed getter before SetValue.
//  - The lease API (lease/release/eligibility) checks the owner thread before reading
//    any lease state; off-thread calls are counted refusals with no cleanup (R1446).
#pragma once
#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <thread>
#include <vector>

extern "C" {
#include "reframework/API.h"
}
#include "re2net/core/engine_bridge.hpp"

namespace re2net::adapter {

struct Resolved {
    // types
    REFrameworkTypeDefinitionHandle door = nullptr, peeked_work = nullptr, component = nullptr, game_object = nullptr,
        transform = nullptr, scene_mgr = nullptr, scene = nullptr, string = nullptr, player_mgr = nullptr,
        player_condition = nullptr, vec3 = nullptr, array = nullptr;
    // door methods/fields
    REFrameworkMethodHandle door_is_opened = nullptr, door_opened_side = nullptr, door_is_locked = nullptr,
        door_request_from_npc = nullptr, door_on_opened = nullptr, door_center = nullptr, door_calc_side = nullptr;
    REFrameworkFieldHandle door_peeked_work = nullptr, door_peeked_rno = nullptr;
    REFrameworkFieldHandle pw_value = nullptr, pw_speed = nullptr, pw_side = nullptr, pw_motion_layer = nullptr;
    // generic
    REFrameworkMethodHandle comp_game_object = nullptr, go_name = nullptr, go_transform = nullptr, tr_position = nullptr,
        mgr_current_scene = nullptr, scene_find_components = nullptr, string_equals = nullptr, pm_current_player = nullptr,
        array_count = nullptr, array_item = nullptr;
    REFrameworkFieldHandle vec_x = nullptr, vec_y = nullptr, vec_z = nullptr;
    // door-scoped eligibility (optional: missing => eligibility unavailable, nothing else changes)
    REFrameworkMethodHandle door_update_peeked = nullptr, door_update_count = nullptr, door_collect = nullptr,
        array_set_value = nullptr;
};

class ReEngineBridge final : public core::EngineBridge {
public:
    static constexpr size_t kMaxDoorScan = 256, kMaxActorScan = 16;

    // Metadata-only preflight (TDB lookups and signature checks, no engine method call).
    bool preflight(const REFrameworkSDKData* sdk, std::string& why);
    void set_witness_installed(bool ok) { witness_ok_ = ok; }
    void set_build_gate(bool ok) { build_gate_ok_ = ok; }
    // Called from the onOpened pre-hook with the hook's raw arguments. Counts only an
    // event whose receiver is the door of the invocation active on this thread.
    static void on_opened_witnessed(int argc, void** argv) noexcept;

    // The one engine thread that owns this bridge's mutable state (published atomically;
    // the plugin sets it from its first engine callback). Hooks on any other thread read
    // no lease/report/binding state, and mutations/leases are refused off it.
    static void set_engine_thread(std::thread::id id);

    // Door-scoped co-op eligibility (see core EligibilityReport). The plugin hooks the
    // two engine consumers of the candidate list (updatePeeked, updateCount: scope
    // pre/post) and the list builder (collectPlCharactors: post). collectPlCharactors'
    // own `this` is optimized away in the exact build, so the door is taken only from the
    // enclosing consumer's receiver (argv[1]).
    // set_hook_permit: the authority the hook re-checks at entry and at its final fence,
    // called with the exact leased (door, actor) refs. The plugin answers: not blocked AND
    // the core's current operation holds exactly this lease with its full pure-state write
    // permission (DoorCore::lease_permit). Pure state, engine thread, must not call the
    // engine. Unset = every injection refused.
    using HookPermit = std::function<bool(core::ObjRef door, core::ObjRef actor)>;
    const Resolved& resolved() const { return r_; }
    void set_eligibility_hooks(bool ok) { eligibility_hooks_ok_ = ok; }
    void set_hook_permit(HookPermit permit) { hook_permit_ = std::move(permit); }
    static void on_door_scope_enter(int argc, void** argv) noexcept;
    static void on_door_scope_exit() noexcept;
    static void on_candidates_built(void** ret_val) noexcept;
    static void begin_frame() noexcept;   // engine-thread callback start: an unbalanced scope stack is reset and counted
    bool lease_eligibility(core::ObjRef door, core::ObjRef actor) override;
    void release_eligibility() noexcept override;
    core::EligibilityReport eligibility() const override;

    core::EngineCaps caps() const override;
    core::Lookup resolve_door(const core::DoorKey& key) override;
    core::Lookup resolve_actor(core::ActorRole who) override;
    bool still_valid(core::ObjRef ref) override;
    std::optional<float> distance(core::ObjRef actor, core::ObjRef door) override;
    core::Side actor_side(core::ObjRef actor, core::ObjRef door) override;
    core::InvokeResult open_by_actor(core::ObjRef door, core::ObjRef actor, const core::Permit& permit) override;
    core::InvokeResult open_mirror(core::ObjRef door, core::ObjRef actor, core::Side side, const core::Permit& permit) override;
    core::FollowStatus follow(core::ObjRef door, float target_value) override;
    core::DoorSample sample(core::ObjRef door) override;

    std::string last_error() const { return last_error_; }
    uint64_t invoke_errors() const { return invoke_errors_; }

private:
    struct Call {
        bool ok = false;          // REFRAMEWORK_ERROR_NONE and no managed exception
        bool entered = false;     // the engine method may have run (ok, or managed exception)
        bool exception = false;
        unsigned char bytes[128]{};
    };
    struct Scan {                 // bounded enumeration result
        bool complete = false;    // every element was visited within the bound
        std::vector<void*> items;
    };
    struct Binding {              // what an ObjRef serial was issued for
        void* ptr = nullptr;
        void* scene = nullptr;
        uint64_t serial = 0;
    };
    struct Found {
        core::LookupStatus status = core::LookupStatus::Error;
        void* ptr = nullptr;
    };

    Call invoke(REFrameworkMethodHandle m, void* thisptr, std::vector<void*> args = {});
    void* object_of(const Call& c) const;
    std::optional<bool> bool_of(const Call& c) const;
    std::optional<core::Side> side_of(const Call& c) const;
    std::optional<std::array<float, 3>> xyz_of(const Call& c) const;   // via.vec3 return, full XYZ

    void* current_scene();
    Scan components_of(void* scene, REFrameworkTypeDefinitionHandle type, size_t cap);
    bool name_equals(void* game_object, const char* name);
    void* game_object_of(void* component);
    std::optional<std::array<float, 3>> position_of(void* game_object);
    Found find_door(void* scene, const core::DoorKey& key);
    Found find_actor(void* scene, core::ActorRole who);
    core::Lookup bind(Binding& b, uint64_t token, void* scene, const Found& f);
    void* by_ref(core::ObjRef ref);
    std::optional<float> peeked_value(void* door, core::Side side, std::optional<float>* speed, core::Tri* layer);
    void inject_partner(void* candidates);   // inside the leased door's own update only
    bool hook_permit_now() const;             // active lease + pure hook permit (no managed call)
    bool lease_identity_current();            // scene + bindings + fresh unique P2 (managed reads)
    void revoke_in_hook() noexcept;            // counted, state-only lease release

    REFrameworkTypeDefinitionHandle type(const char* name);
    REFrameworkMethodHandle method(REFrameworkTypeDefinitionHandle t, const char* name, const char* ret,
                                   std::initializer_list<const char*> params, bool is_static = false);
    REFrameworkFieldHandle field(REFrameworkTypeDefinitionHandle t, const char* name, const char* type_name);
    bool enum_is_int32(const char* enum_name);
    std::string full_name(REFrameworkTypeDefinitionHandle t) const;
    bool fail(std::string& why, const std::string& what);

    const REFrameworkSDKData* sdk_ = nullptr;
    Resolved r_{};
    bool ok_ = false, witness_ok_ = false, build_gate_ok_ = false;
    bool eligibility_meta_ok_ = false, eligibility_hooks_ok_ = false;
    std::string eligibility_detail_;
    bool in_engine_call_ = false;   // mutation reentrancy guard
    // The single eligibility lease (engine thread only).
    struct Lease {
        bool active = false;
        void* door = nullptr;
        void* actor = nullptr;      // managed ref held while active
        uint64_t door_serial = 0, actor_serial = 0;
    } lease_{};                       // engine-thread state: read only after owner_here()
    HookPermit hook_permit_;
    std::atomic<uint32_t> foreign_refused_{0};   // the only field an off-thread lease call touches
    core::EligibilityReport report_{};
    std::string detail_, last_error_;
    uint64_t invoke_errors_ = 0;
    core::DoorKey key_{};           // the slice's single door key, for re-resolution by ref
    Binding door_b_, p1_b_, p2_b_;
    uint64_t next_serial_ = 1;
};

}  // namespace re2net::adapter
