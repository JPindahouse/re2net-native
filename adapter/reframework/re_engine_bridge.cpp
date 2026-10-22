#include "re_engine_bridge.hpp"

#include <array>
#include <cmath>
#include <cstring>

namespace re2net::adapter {
using namespace re2net::core;

namespace {
constexpr uint64_t kDoorToken = 100, kP1Token = 1, kP2Token = 2;
constexpr const char* kHunkName = "pl4000";   // supported partner rig identifier; other rigs unsupported here
constexpr float kDisplacedM = 0.05f;

#pragma pack(push, 1)
struct InvokeOut {               // identical layout to reframework::InvokeRet (API.h comment)
    unsigned char bytes[128];
    bool exception_thrown;
};
#pragma pack(pop)
static_assert(sizeof(InvokeOut) == 129, "InvokeRet is 128 bytes + exception flag");

// via.vec3 argument storage (16-byte value type, Single x/y/z at
// 0/4/8, fourth word padding). Passed as ONE pointer slot to this block.
struct alignas(16) Vec3Storage { float x, y, z, padding; };
static_assert(sizeof(Vec3Storage) == 16, "via.vec3 is 16 bytes");

// The invocation whose onOpened events count, per thread.
struct Witness {
    bool active = false;
    void* receiver = nullptr;     // the requested door
    uint64_t invocation = 0;
    uint32_t matched = 0, foreign = 0, unattributable = 0;
};
thread_local Witness t_witness;
uint64_t g_invocation = 0;        // engine thread only

// Scoped flag: refuses re-entrant engine mutations and always clears.
struct EngineCallGuard {
    bool& flag;
    explicit EngineCallGuard(bool& f) : flag(f) { flag = true; }
    ~EngineCallGuard() { flag = false; }
};

// Which door's own candidate consumer (updatePeeked/updateCount) is running on this
// thread. nullptr entries are sentinels: another door, no lease, or the wrong thread.
// Depth beyond the array is counted but never matched.
struct ScopeStack {
    static constexpr int kMax = 8;
    void* entry[kMax]{};
    int depth = 0;
};
thread_local ScopeStack t_scope;
// The single bridge instance and the engine thread that owns all of its mutable state,
// both published atomically. Every hook resolves
// owner_here() FIRST: on any other thread it gets nullptr and reads no lease/report/
// binding state at all, so concurrent foreign callbacks cannot race the engine thread.
std::atomic<ReEngineBridge*> g_owner{nullptr};
std::atomic<std::thread::id> g_engine_thread{};
ReEngineBridge* owner_here() {
    ReEngineBridge* b = g_owner.load(std::memory_order_acquire);
    if (!b) return nullptr;
    if (g_engine_thread.load(std::memory_order_acquire) != std::this_thread::get_id()) return nullptr;
    return b;
}
}  // namespace

void ReEngineBridge::set_engine_thread(std::thread::id id) { g_engine_thread.store(id, std::memory_order_release); }

// ------------------------------------------------------------------ eligibility hooks
// All three hook entries are noexcept with a fail-closed boundary (finding 3): a C++
// exception never propagates into the engine's call; on the engine thread it is counted
// and the lease is released (state-only), so no later injection runs on that authority.
void ReEngineBridge::on_door_scope_enter(int argc, void** argv) noexcept {
    try {
        ScopeStack& s = t_scope;   // thread-local: touching it is always safe
        void* door = nullptr;
        if (ReEngineBridge* b = owner_here()) {
            if (b->lease_.active && argc >= 2 && argv && argv[1] == b->lease_.door) {
                door = argv[1];
                ++b->report_.scopes;
            }
        }
        if (s.depth < ScopeStack::kMax) s.entry[s.depth] = door;
        ++s.depth;
    } catch (...) {
        if (ReEngineBridge* b = owner_here()) { ++b->report_.hook_faults; b->revoke_in_hook(); }
    }
}

void ReEngineBridge::on_door_scope_exit() noexcept {
    ScopeStack& s = t_scope;
    if (s.depth > 0) --s.depth;
}

void ReEngineBridge::on_candidates_built(void** ret_val) noexcept {
    ReEngineBridge* b = owner_here();   // thread exclusion before ANY engine-owned state
    if (!b) return;
    try {
        ScopeStack& s = t_scope;
        if (!b->lease_.active || s.depth <= 0 || s.depth > ScopeStack::kMax) return;
        void* top = s.entry[s.depth - 1];
        if (!top || top != b->lease_.door) return;
        if (!ret_val || !*ret_val) { ++b->report_.refused; return; }
        b->inject_partner(*ret_val);
    } catch (...) {
        ++b->report_.hook_faults;
        b->revoke_in_hook();
    }
}

void ReEngineBridge::begin_frame() noexcept {
    ScopeStack& s = t_scope;
    if (s.depth != 0) {
        if (ReEngineBridge* b = owner_here()) ++b->report_.unbalanced;   // a post hook did not run (e.g. another hook skipped)
        s.depth = 0;
    }
}

void ReEngineBridge::revoke_in_hook() noexcept {
    if (!lease_.active) return;
    ++report_.revoked_in_hook;
    release_eligibility();
}

// The lease's pure authority (R1446 static review findings 1 and 3): an active lease, and
// the plugin's hook permit for exactly the leased (door, actor) refs: plugin not blocked,
// and the core's CURRENT operation still holds this lease with its full pure-state write
// permission (revocation/cancel/overflow/fault, local connection epoch, session/consent/
// playing, fence, selection, queued holds). No managed call. A missing permit is a
// refusal, never a default. Engine thread only.
bool ReEngineBridge::hook_permit_now() const {
    if (!lease_.active || !hook_permit_) return false;
    return hook_permit_(ObjRef{kDoorToken, lease_.door_serial}, ObjRef{kP2Token, lease_.actor_serial});
}

// The lease's CURRENT native identity (managed reads): the native scene object is the one
// the door and actor were bound in, the bindings still carry the leased serials/addresses,
// and the partner re-resolves uniquely to the same object now. Holding a managed ref keeps
// an object alive; it does not make it the current partner. The door itself is the
// receiver of the update the engine is running. Same-address reuse is not detectable.
bool ReEngineBridge::lease_identity_current() {
    if (!lease_.active) return false;
    void* scene = current_scene();
    if (!scene || scene != door_b_.scene || scene != p2_b_.scene) return false;
    if (door_b_.ptr != lease_.door || door_b_.serial != lease_.door_serial) return false;
    if (p2_b_.ptr != lease_.actor || p2_b_.serial != lease_.actor_serial) return false;
    Found f = find_actor(scene, ActorRole::P2);
    return f.status == LookupStatus::Found && f.ptr == lease_.actor;
}

// The freshly built [CurrentPlayer, NPC PL2000, NPC PL3000] list of the leased door.
// Slot 0 (CurrentPlayer) and any real NPC are never touched; the actor goes only into an
// empty NPC slot, through the managed array setter, and is read back.
// The mutation guard is HELD across every managed callback below, so a re-entrant collect
// (or a re-entrant open) during count/item/identity/setter/readback is refused.
// Fixed order (R1446 static review findings 1-2):
//   1. entry: the pure permit (no managed read yet);
//   2. every managed read: the array count/items, THEN the current identity (scene,
//      bindings, fresh unique P2), so a replacement revealed by the array callbacks counts;
//   3. the FINAL fence: the same active lease and actor, and the pure permit, with NO
//      managed getter between it and SetValue.
// Any identity/permit failure releases the lease here; nothing falls back to anything.
// Not claimed: cancellation after the native setter is entered, or detection of a
// same-address (ABA) replacement inside the native setter.
void ReEngineBridge::inject_partner(void* arr) {
    if (in_engine_call_) { ++report_.reentry_refused; return; }
    EngineCallGuard guard(in_engine_call_);
    if (!hook_permit_now()) { revoke_in_hook(); return; }
    void* const actor = lease_.actor;
    Call cc = invoke(r_.array_count, arr);
    if (!cc.ok) { ++report_.refused; return; }
    int32_t n = 0;
    std::memcpy(&n, cc.bytes, sizeof(n));
    if (n != 3) { ++report_.refused; return; }   // not the exact-build shape
    void* e[3]{};
    for (int32_t i = 0; i < 3; ++i) {
        Call ci = invoke(r_.array_item, arr, {reinterpret_cast<void*>(static_cast<intptr_t>(i))});
        if (!ci.ok) { ++report_.refused; return; }
        e[i] = object_of(ci);
    }
    if (!lease_.active || lease_.actor != actor) return;   // released by a callback during the reads
    if (e[0] == actor || e[1] == actor || e[2] == actor) { ++report_.already_member; return; }
    int slot = !e[1] ? 1 : !e[2] ? 2 : -1;
    if (slot < 0) { ++report_.no_free_slot; return; }
    if (!lease_identity_current()) { revoke_in_hook(); return; }   // last managed reads
    std::vector<void*> args{actor, reinterpret_cast<void*>(static_cast<intptr_t>(slot))};
    // final fence: pure state only, immediately before the only write
    if (!lease_.active || lease_.actor != actor || !hook_permit_now()) { revoke_in_hook(); return; }
    Call cs = invoke(r_.array_set_value, arr, std::move(args));
    if (!cs.ok) { ++report_.refused; return; }
    Call cv = invoke(r_.array_item, arr, {reinterpret_cast<void*>(static_cast<intptr_t>(slot))});
    if (!lease_.active || object_of(cv) != actor) { ++report_.refused; return; }
    ++report_.injected;
}

bool ReEngineBridge::lease_eligibility(ObjRef door, ObjRef actor) {
    // Owner identity FIRST (R1446 static review finding 4): off the engine owner thread
    // nothing mutable is read, nothing is released and no managed API is called. Any
    // cleanup of the owner's lease stays owner-thread work.
    if (owner_here() != this) { foreign_refused_.fetch_add(1, std::memory_order_relaxed); return false; }
    if (!ok_ || !build_gate_ok_ || !eligibility_meta_ok_ || !eligibility_hooks_ok_ || door.token != kDoorToken ||
        actor.token != kP2Token) {
        release_eligibility();
        return false;
    }
    void* d = by_ref(door);
    void* a = by_ref(actor);
    if (!d || !a) { release_eligibility(); return false; }
    bool same_pair = lease_.door_serial == door.incarnation && lease_.actor_serial == actor.incarnation;
    if (lease_.active && same_pair && lease_.door == d && lease_.actor == a) return true;
    release_eligibility();
    if (!same_pair) report_ = {};   // a new door/actor pair starts fresh evidence
    sdk_->managed_object->add_ref(static_cast<REFrameworkManagedObjectHandle>(a));   // alive while leased
    lease_.door = d;
    lease_.actor = a;
    lease_.door_serial = door.incarnation;
    lease_.actor_serial = actor.incarnation;
    lease_.active = true;
    return true;
}

void ReEngineBridge::release_eligibility() noexcept {
    if (owner_here() != this) { foreign_refused_.fetch_add(1, std::memory_order_relaxed); return; }   // owner-thread work
    if (!lease_.active) return;
    lease_.active = false;
    if (lease_.actor && sdk_ && sdk_->managed_object && sdk_->managed_object->release)
        sdk_->managed_object->release(static_cast<REFrameworkManagedObjectHandle>(lease_.actor));
    lease_.door = nullptr;
    lease_.actor = nullptr;
}

EligibilityReport ReEngineBridge::eligibility() const {
    EligibilityReport r;
    if (owner_here() == this) {   // off-thread: no lease/report read (reports nothing held)
        r = report_;
        r.active = lease_.active;
    }
    r.foreign_thread_refused = foreign_refused_.load(std::memory_order_relaxed);
    return r;
}

// REFramework passes a managed method's hook arguments as raw values: argv[0] is the VM
// thread context and argv[1] is `this` for an instance method.
// A matching pre-hook proves call ENTRY only: any hook may skip the original.
// If the receiver ever failed to match, the result fails closed (on_opened False -> core
// no_open_mutation), never True. Thread-local state only.
void ReEngineBridge::on_opened_witnessed(int argc, void** argv) noexcept {
    Witness& w = t_witness;
    if (!w.active) return;                 // not inside our own invocation on this thread
    if (argc < 2 || !argv) { ++w.unattributable; return; }
    if (argv[1] == w.receiver) ++w.matched;
    else ++w.foreign;                      // another door (nested or unrelated): never the target's evidence
}

// ------------------------------------------------------------------ metadata
bool ReEngineBridge::fail(std::string& why, const std::string& what) {
    if (why.empty()) why = what;
    return false;
}

std::string ReEngineBridge::full_name(REFrameworkTypeDefinitionHandle t) const {
    if (!t) return {};
    char buf[512];
    unsigned int len = 0;
    if (sdk_->type_definition->get_full_name(t, buf, sizeof(buf), &len) != REFRAMEWORK_ERROR_NONE) return {};
    return std::string(buf, strnlen(buf, sizeof(buf)));
}

REFrameworkTypeDefinitionHandle ReEngineBridge::type(const char* name) {
    return sdk_->tdb->find_type(sdk_->functions->get_tdb(), name);
}

REFrameworkMethodHandle ReEngineBridge::method(REFrameworkTypeDefinitionHandle t, const char* name, const char* ret,
                                               std::initializer_list<const char*> params, bool is_static) {
    if (!t) return nullptr;
    REFrameworkMethodHandle m = sdk_->type_definition->find_method(t, name);
    if (!m) { detail_ += std::string(" missing_method:") + name; return nullptr; }
    if (!ret || full_name(sdk_->method->get_return_type(m)) != ret) { detail_ += std::string(" ret_mismatch:") + name; return nullptr; }
    if (sdk_->method->is_static(m) != is_static) { detail_ += std::string(" static_mismatch:") + name; return nullptr; }
    if (sdk_->method->get_num_params(m) != params.size()) { detail_ += std::string(" arity_mismatch:") + name; return nullptr; }
    if (params.size()) {
        REFrameworkMethodParameter ps[8]{};
        unsigned int n = 0;
        if (params.size() > 8 || sdk_->method->get_params(m, ps, sizeof(ps), &n) != REFRAMEWORK_ERROR_NONE || n != params.size()) {
            detail_ += std::string(" params_unreadable:") + name;
            return nullptr;
        }
        size_t i = 0;
        for (const char* p : params) {
            if (full_name(ps[i].t) != p) { detail_ += std::string(" param_mismatch:") + name; return nullptr; }
            ++i;
        }
    }
    return m;
}

REFrameworkFieldHandle ReEngineBridge::field(REFrameworkTypeDefinitionHandle t, const char* name, const char* type_name) {
    if (!t) return nullptr;
    REFrameworkFieldHandle f = sdk_->type_definition->find_field(t, name);
    if (!f) { detail_ += std::string(" missing_field:") + name; return nullptr; }
    if (sdk_->field->is_static(f)) { detail_ += std::string(" static_field:") + name; return nullptr; }
    if (type_name && full_name(sdk_->field->get_type(f)) != type_name) { detail_ += std::string(" field_type:") + name; return nullptr; }
    return f;
}

// Enum underlying type from TDB metadata: the instance field `value__`. Not
// get_underlying_type, which runs managed reflection.
bool ReEngineBridge::enum_is_int32(const char* enum_name) {
    auto t = type(enum_name);
    if (!t) return false;
    REFrameworkFieldHandle f = sdk_->type_definition->find_field(t, "value__");
    return f && !sdk_->field->is_static(f) && full_name(sdk_->field->get_type(f)) == "System.Int32" &&
           sdk_->type_definition->get_valuetype_size(t) == 4;
}

bool ReEngineBridge::preflight(const REFrameworkSDKData* sdk, std::string& why) {
    sdk_ = sdk;
    if (!sdk || !sdk->functions || !sdk->tdb || !sdk->type_definition || !sdk->method || !sdk->field || !sdk->managed_object)
        return fail(why, "sdk_tables_missing");
    if (!sdk->functions->get_tdb || !sdk->functions->typeof_ || !sdk->functions->get_managed_singleton ||
        !sdk->functions->get_native_singleton || !sdk->functions->create_managed_string_normal || !sdk->method->invoke ||
        !sdk->method->is_static || !sdk->field->get_offset_from_fieldptr || !sdk->field->get_data_raw)
        return fail(why, "sdk_functions_missing");

    const char* kDoor = "app.ropeway.gimmick.action.GimmickDoorBase";
    const char* kSide = "app.ropeway.gimmick.action.GimmickDoorBase.SideType";
    const char* kRno = "app.ropeway.gimmick.action.GimmickDoorBase.PeekedRoutine";
    r_.door = type(kDoor);
    r_.peeked_work = type("app.ropeway.gimmick.action.GimmickDoorBase.PeekedWork");
    r_.component = type("via.Component");
    r_.game_object = type("via.GameObject");
    r_.transform = type("via.Transform");
    r_.scene_mgr = type("via.SceneManager");
    r_.scene = type("via.Scene");
    r_.string = type("System.String");
    r_.player_mgr = type("app.ropeway.PlayerManager");
    r_.player_condition = type("app.ropeway.survivor.player.PlayerCondition");
    r_.vec3 = type("via.vec3");
    r_.array = type("System.Array");
    for (auto [t, n] : {std::pair{r_.door, "door"}, {r_.peeked_work, "peeked_work"}, {r_.component, "component"},
                        {r_.game_object, "game_object"}, {r_.transform, "transform"}, {r_.scene_mgr, "scene_mgr"},
                        {r_.scene, "scene"}, {r_.string, "string"}, {r_.player_mgr, "player_mgr"},
                        {r_.player_condition, "player_condition"}, {r_.vec3, "vec3"}, {r_.array, "array"}})
        if (!t) detail_ += std::string(" missing_type:") + n;

    // Exact-build contracts (checked native type metadata).
    r_.door_is_opened = method(r_.door, "get_IsOpened", "System.Boolean", {});
    r_.door_opened_side = method(r_.door, "get_OpenedSide", kSide, {});
    r_.door_is_locked = method(r_.door, "get_IsLocked", "System.Boolean", {});
    r_.door_request_from_npc = method(r_.door, "requestOpenFromNPC", "System.Boolean", {"via.GameObject"});
    r_.door_on_opened = method(r_.door, "onOpened", "System.Void", {});
    r_.door_center = method(r_.door, "get_Center", "via.vec3", {});
    r_.door_calc_side = method(r_.door, "calcSide(via.vec3)", kSide, {"via.vec3"});
    r_.door_peeked_work = field(r_.door, "_PeekedWork", "app.ropeway.gimmick.action.GimmickDoorBase.PeekedWork[]");
    r_.door_peeked_rno = field(r_.door, "_PeekedRno", kRno);
    r_.pw_value = field(r_.peeked_work, "Value", "System.Single");
    r_.pw_speed = field(r_.peeked_work, "Speed", "System.Single");
    r_.pw_side = field(r_.peeked_work, "Side", kSide);
    r_.pw_motion_layer = field(r_.peeked_work, "MotionLayer", "via.motion.TreeLayer");
    r_.comp_game_object = method(r_.component, "get_GameObject", "via.GameObject", {});
    r_.go_name = method(r_.game_object, "get_Name", "System.String", {});
    r_.go_transform = method(r_.game_object, "get_Transform", "via.Transform", {});
    r_.tr_position = method(r_.transform, "get_Position", "via.vec3", {});
    r_.mgr_current_scene = method(r_.scene_mgr, "get_CurrentScene", "via.Scene", {}, /*is_static=*/true);
    r_.scene_find_components = method(r_.scene, "findComponents(System.Type)", "via.Component[]", {"System.Type"});
    r_.string_equals = method(r_.string, "Equals(System.String)", "System.Boolean", {"System.String"});
    r_.pm_current_player = method(r_.player_mgr, "get_CurrentPlayer", "via.GameObject", {});
    r_.array_count = method(r_.array, "get_Count", "System.Int32", {});
    r_.array_item = method(r_.array, "get_Item(System.Int32)", "System.Object", {"System.Int32"});
    r_.vec_x = field(r_.vec3, "x", "System.Single");
    r_.vec_y = field(r_.vec3, "y", "System.Single");
    r_.vec_z = field(r_.vec3, "z", "System.Single");

    // Enums are read as 32-bit integers only when their metadata says so.
    for (const char* en : {kSide, kRno})
        if (!enum_is_int32(en)) detail_ += std::string(" enum_not_int32:") + en;
    // via.vec3 exact layout (checked native value layout): value type, 16 bytes, x/y/z at 0/4/8.
    if (r_.vec3 && (!sdk_->type_definition->is_valuetype(r_.vec3) || sdk_->type_definition->get_valuetype_size(r_.vec3) != 16))
        detail_ += " vec3_layout";
    if (r_.vec_x && r_.vec_y && r_.vec_z &&
        (sdk_->field->get_offset_from_fieldptr(r_.vec_x) != 0 || sdk_->field->get_offset_from_fieldptr(r_.vec_y) != 4 ||
         sdk_->field->get_offset_from_fieldptr(r_.vec_z) != 8))
        detail_ += " vec3_offsets";

    // Optional: door-scoped eligibility (absent => eligibility_ok false, nothing else changes).
    {
        std::string saved = detail_;
        detail_.clear();
        r_.door_update_peeked = method(r_.door, "updatePeeked", "System.Void", {});
        r_.door_update_count = method(r_.door, "updateCount", "System.Void", {});
        r_.door_collect = method(r_.door, "collectPlCharactors", "via.GameObject[]", {});
        r_.array_set_value = method(r_.array, "SetValue(System.Object, System.Int32)", "System.Void",
                                    {"System.Object", "System.Int32"});
        eligibility_meta_ok_ = detail_.empty() && sdk->managed_object->add_ref && sdk->managed_object->release;
        eligibility_detail_ = detail_;
        detail_ = saved;
    }

    ok_ = detail_.empty();
    if (!ok_) return fail(why, "contract:" + detail_.substr(0, 200));
    g_owner.store(this, std::memory_order_release);   // before any hook is registered
    detail_ = std::string("contracts ok; follow disabled; actor_side via calcSide(via.vec3); eligibility ") +
              (eligibility_meta_ok_ ? "metadata ok" : "unavailable:" + eligibility_detail_.substr(0, 80));
    return true;
}

EngineCaps ReEngineBridge::caps() const {
    EngineCaps c;
    c.build_ok = ok_ && build_gate_ok_;   // reviewed executable digest admitted at initialize
    c.api_ok = ok_;
    c.door_types_ok = ok_;
    // requestOpenFromNPC is the exact-build actor-explicit candidate. Its HUNK pair/Jack
    // compatibility is UNPROVEN; the core treats true-without-onOpened as no mutation.
    c.actor_open_ok = c.build_ok && witness_ok_;
    c.mirror_open_ok = c.build_ok && witness_ok_;
    c.follow_ok = false;
    c.witness_ok = witness_ok_;
    c.eligibility_ok = c.build_ok && eligibility_meta_ok_ && eligibility_hooks_ok_;
    c.detail = build_gate_ok_ ? detail_ : "executable digest gate not passed";
    return c;
}

// ------------------------------------------------------------------ invoke helpers
ReEngineBridge::Call ReEngineBridge::invoke(REFrameworkMethodHandle m, void* thisptr, std::vector<void*> args) {
    Call c;
    if (!m) return c;
    alignas(16) InvokeOut out{};
    REFrameworkResult res = sdk_->method->invoke(m, thisptr, args.empty() ? nullptr : args.data(),
                                                 static_cast<unsigned int>(args.size() * sizeof(void*)), &out, sizeof(out));
    if (res == REFRAMEWORK_ERROR_NONE) {
        c.entered = true;
        c.exception = out.exception_thrown;
        c.ok = !out.exception_thrown;
        std::memcpy(c.bytes, out.bytes, sizeof(c.bytes));
    } else if (res == REFRAMEWORK_ERROR_EXCEPTION) {
        c.entered = true;
        c.exception = true;
    } else {
        ++invoke_errors_;
        last_error_ = "invoke_result_" + std::to_string(res);
    }
    return c;
}

void* ReEngineBridge::object_of(const Call& c) const {
    if (!c.ok) return nullptr;
    void* p = nullptr;
    std::memcpy(&p, c.bytes, sizeof(p));
    return p;
}

std::optional<bool> ReEngineBridge::bool_of(const Call& c) const {
    if (!c.ok) return std::nullopt;
    if (c.bytes[0] > 1) return std::nullopt;
    return c.bytes[0] == 1;
}

std::optional<Side> ReEngineBridge::side_of(const Call& c) const {
    if (!c.ok) return std::nullopt;
    int32_t v = 0;
    std::memcpy(&v, c.bytes, sizeof(v));
    if (v == 0) return Side::A;
    if (v == 1) return Side::B;
    return Side::Unknown;   // NONE or another value: never mapped to A/B
}

// Full via.vec3 return: inline in InvokeRet.bytes, x/y/z at the
// preflight-verified offsets 0/4/8.
std::optional<std::array<float, 3>> ReEngineBridge::xyz_of(const Call& c) const {
    if (!c.ok) return std::nullopt;
    std::array<float, 3> v{};
    std::memcpy(&v[0], c.bytes + 0, sizeof(float));
    std::memcpy(&v[1], c.bytes + 4, sizeof(float));
    std::memcpy(&v[2], c.bytes + 8, sizeof(float));
    for (float f : v) if (!std::isfinite(f) || std::fabs(f) > 1e5f) return std::nullopt;
    return v;
}

// ------------------------------------------------------------------ resolution
void* ReEngineBridge::current_scene() {
    return object_of(invoke(r_.mgr_current_scene, nullptr));   // static method
}

// Visits every element of the found array, nulls included, but only when the array's
// length is within `cap`; otherwise the scan is incomplete and nothing is claimed.
ReEngineBridge::Scan ReEngineBridge::components_of(void* scene, REFrameworkTypeDefinitionHandle t, size_t cap) {
    Scan s;
    if (!scene) return s;
    std::string tn = full_name(t);
    void* type_obj = sdk_->functions->typeof_(tn.c_str());
    if (!type_obj) return s;
    void* arr = object_of(invoke(r_.scene_find_components, scene, {type_obj}));
    if (!arr) return s;
    Call cc = invoke(r_.array_count, arr);
    if (!cc.ok) return s;
    int32_t n = 0;
    std::memcpy(&n, cc.bytes, sizeof(n));
    if (n < 0 || static_cast<size_t>(n) > cap) return s;   // overflow: Unsupported, never "unique"
    for (int32_t i = 0; i < n; ++i) {
        Call ci = invoke(r_.array_item, arr, {reinterpret_cast<void*>(static_cast<intptr_t>(i))});
        if (!ci.ok) return s;                              // an unreadable element: incomplete
        if (void* e = object_of(ci)) s.items.push_back(e);
    }
    s.complete = true;
    return s;
}

bool ReEngineBridge::name_equals(void* go, const char* name) {
    void* str = object_of(invoke(r_.go_name, go));
    if (!str) return false;
    void* target = sdk_->functions->create_managed_string_normal(name);
    if (!target) return false;
    auto b = bool_of(invoke(r_.string_equals, str, {target}));
    return b.value_or(false);
}

void* ReEngineBridge::game_object_of(void* component) { return object_of(invoke(r_.comp_game_object, component)); }

std::optional<std::array<float, 3>> ReEngineBridge::position_of(void* go) {
    void* tr = object_of(invoke(r_.go_transform, go));
    if (!tr) return std::nullopt;
    return xyz_of(invoke(r_.tr_position, tr));
}

ReEngineBridge::Found ReEngineBridge::find_door(void* scene, const DoorKey& key) {
    if (!scene) return {LookupStatus::NotLoaded, nullptr};
    Scan s = components_of(scene, r_.door, kMaxDoorScan);
    if (!s.complete) return {LookupStatus::Unsupported, nullptr};
    void* found = nullptr;
    int count = 0;
    for (void* d : s.items) {
        void* go = game_object_of(d);
        if (go && name_equals(go, key.name.c_str())) { ++count; if (!found) found = d; }
    }
    if (count == 0) return {LookupStatus::Missing, nullptr};
    if (count > 1) return {LookupStatus::Duplicate, nullptr};
    return {LookupStatus::Found, found};
}

ReEngineBridge::Found ReEngineBridge::find_actor(void* scene, ActorRole who) {
    void* pm = sdk_->functions->get_managed_singleton("app.ropeway.PlayerManager");
    void* p1 = pm ? object_of(invoke(r_.pm_current_player, pm)) : nullptr;
    if (who == ActorRole::P1) return p1 ? Found{LookupStatus::Found, p1} : Found{LookupStatus::Missing, nullptr};
    if (!scene) return {LookupStatus::NotLoaded, nullptr};
    Scan s = components_of(scene, r_.player_condition, kMaxActorScan);
    if (!s.complete) return {LookupStatus::Unsupported, nullptr};
    void* found = nullptr;
    int count = 0;
    for (void* c : s.items) {
        void* go = game_object_of(c);
        if (!go || go == p1) continue;
        if (name_equals(go, kHunkName)) { ++count; found = go; }
    }
    if (count == 0) return {LookupStatus::Missing, nullptr};
    if (count > 1) return {LookupStatus::Duplicate, nullptr};
    return {LookupStatus::Found, found};
}

Lookup ReEngineBridge::bind(Binding& b, uint64_t token, void* scene, const Found& f) {
    if (f.status != LookupStatus::Found) { b = {}; return {f.status, {}}; }
    b = Binding{f.ptr, scene, next_serial_++};
    return {LookupStatus::Found, {token, b.serial}};
}

Lookup ReEngineBridge::resolve_door(const DoorKey& key) {
    if (!ok_ || !build_gate_ok_) return {LookupStatus::Unsupported, {}};
    key_ = key;
    void* scene = current_scene();
    return bind(door_b_, kDoorToken, scene, find_door(scene, key));
}

Lookup ReEngineBridge::resolve_actor(ActorRole who) {
    if (!ok_ || !build_gate_ok_) return {LookupStatus::Unsupported, {}};
    void* scene = current_scene();
    Found f = find_actor(scene, who);
    if (f.status != LookupStatus::Found && f.status != LookupStatus::Unsupported) f.status = LookupStatus::Missing;
    return bind(who == ActorRole::P1 ? p1_b_ : p2_b_, who == ActorRole::P1 ? kP1Token : kP2Token, scene, f);
}

// Same serial, same scene object, and a fresh unique re-resolution to the same address.
void* ReEngineBridge::by_ref(ObjRef ref) {
    Binding* b = ref.token == kDoorToken ? &door_b_ : ref.token == kP1Token ? &p1_b_ : ref.token == kP2Token ? &p2_b_ : nullptr;
    if (!b || !b->ptr || ref.incarnation != b->serial) return nullptr;
    void* scene = current_scene();
    if (!scene || scene != b->scene) return nullptr;
    Found f = ref.token == kDoorToken ? find_door(scene, key_)
                                      : find_actor(scene, ref.token == kP1Token ? ActorRole::P1 : ActorRole::P2);
    return f.status == LookupStatus::Found && f.ptr == b->ptr ? f.ptr : nullptr;
}

bool ReEngineBridge::still_valid(ObjRef ref) { return ok_ && build_gate_ok_ && by_ref(ref) != nullptr; }

std::optional<float> ReEngineBridge::distance(ObjRef actor, ObjRef door) {
    void* a = by_ref(actor);
    void* d = by_ref(door);
    if (!a || !d) return std::nullopt;
    auto pa = position_of(a);
    auto pc = xyz_of(invoke(r_.door_center, d));
    if (!pa || !pc) return std::nullopt;
    float dx = (*pa)[0] - (*pc)[0], dz = (*pa)[2] - (*pc)[2];
    // Guard measure: XZ distance floored to 0.1 m
    return std::floor(std::sqrt(dx * dx + dz * dz) * 10.0f) / 10.0f;
}

// GimmickDoorBase.calcSide(via.vec3) on the selected actor's fresh FULL position.
// Synchronous: the argument block lives on this frame through invoke() and is never
// queued. SideType 0/1 -> A/B; NONE (2) or any other value stays Unknown.
Side ReEngineBridge::actor_side(ObjRef actor, ObjRef door) {
    if (!ok_ || !build_gate_ok_ || !r_.door_calc_side) return Side::Unknown;
    void* a = by_ref(actor);
    void* d = by_ref(door);
    if (!a || !d) return Side::Unknown;
    auto p = position_of(a);
    if (!p) return Side::Unknown;
    Vec3Storage pos{(*p)[0], (*p)[1], (*p)[2], 0.0f};
    Call c = invoke(r_.door_calc_side, d, {&pos});   // ONE pointer slot to the 16-byte block
    return side_of(c).value_or(Side::Unknown);
}

// ------------------------------------------------------------------ mutations
InvokeResult ReEngineBridge::open_by_actor(ObjRef door, ObjRef actor, const Permit& permit) {
    InvokeResult r;
    if (!ok_ || !build_gate_ok_ || !witness_ok_) { r.status = InvokeStatus::Unsupported; return r; }
    if (owner_here() != this) { r.status = InvokeStatus::Unsupported; return r; }   // engine thread only
    if (in_engine_call_ || t_witness.active) { r.status = InvokeStatus::NestedRefused; return r; }
    EngineCallGuard guard(in_engine_call_);
    void* d = by_ref(door);
    void* a = by_ref(actor);
    if (!d || !a) { r.status = InvokeStatus::Stale; return r; }
    auto before = position_of(a);
    // R1414 static review finding 1: the caller's authority, re-checked AFTER the last
    // managed reads above and immediately before the only mutating call. Denied = not
    // entered. Nothing below can be cancelled once requestOpenFromNPC is entered.
    if (!permit || !permit()) { r.status = InvokeStatus::PermitDenied; return r; }
    t_witness = Witness{true, d, ++g_invocation, 0, 0, 0};
    Call c = invoke(r_.door_request_from_npc, d, {a});
    Witness w = t_witness;
    t_witness = Witness{};
    if (!c.entered) { r.status = InvokeStatus::Unsupported; return r; }
    if (c.exception) r.status = InvokeStatus::Exception;
    else {
        auto b = bool_of(c);
        r.status = !b ? InvokeStatus::Exception : (*b ? InvokeStatus::ReturnedTrue : InvokeStatus::ReturnedFalse);
    }
    r.on_opened = w.matched > 0 ? Tri::True : w.unattributable > 0 ? Tri::Unknown : Tri::False;
    auto after = position_of(a);
    if (before && after) {
        float dx = (*after)[0] - (*before)[0], dz = (*after)[2] - (*before)[2];
        r.actor_displaced = tri(std::sqrt(dx * dx + dz * dz) > kDisplacedM);
    }
    return r;
}

InvokeResult ReEngineBridge::open_mirror(ObjRef door, ObjRef actor, Side, const Permit& permit) {
    // The guest replica door is opened by the same actor-explicit engine action with the
    // local replica of the same partner actor. The host's side is NOT forced: the engine
    // computes the side from the replica actor's own position (requestOpenFromNPC ->
    // calcSide). Nothing compares the host's side with the local opened side (ResultMsg
    // has no side), so no direction or leaf equivalence between the replicas is
    // established, and an OpenBoth is two progress outcomes, not proof that both players
    // passed (R1414 static review finding 5). No second backend is tried.
    return open_by_actor(door, actor, permit);
}

FollowStatus ReEngineBridge::follow(ObjRef, float) {
    return FollowStatus::Unsupported;   // disabled until the raw scale and a supported driver are grounded
}

// ------------------------------------------------------------------ observation
// The value of the PeekedWork element of exactly `side`. No other side's work is ever
// substituted; an unknown side or no matching readable element is Unknown.
std::optional<float> ReEngineBridge::peeked_value(void* door, Side side, std::optional<float>* speed, Tri* layer) {
    if (side != Side::A && side != Side::B) return std::nullopt;
    auto** slot = static_cast<void**>(sdk_->field->get_data_raw(r_.door_peeked_work, door, false));
    void* arr = slot ? *slot : nullptr;
    if (!arr) return std::nullopt;
    Call cc = invoke(r_.array_count, arr);
    if (!cc.ok) return std::nullopt;
    int32_t n = 0;
    std::memcpy(&n, cc.bytes, sizeof(n));
    if (n < 0 || n > 4) return std::nullopt;   // a door has one work per side; anything else is not understood
    const int32_t want = side == Side::A ? 0 : 1;
    std::optional<float> value;
    int matches = 0;
    for (int32_t i = 0; i < n; ++i) {
        void* e = object_of(invoke(r_.array_item, arr, {reinterpret_cast<void*>(static_cast<intptr_t>(i))}));
        if (!e) continue;
        auto* pside = static_cast<int32_t*>(sdk_->field->get_data_raw(r_.pw_side, e, false));
        if (!pside || *pside != want) continue;
        ++matches;
        auto* pv = static_cast<float*>(sdk_->field->get_data_raw(r_.pw_value, e, false));
        auto* ps = static_cast<float*>(sdk_->field->get_data_raw(r_.pw_speed, e, false));
        auto** pl = static_cast<void**>(sdk_->field->get_data_raw(r_.pw_motion_layer, e, false));
        if (!pv || !std::isfinite(*pv)) continue;
        value = *pv;
        *speed = (ps && std::isfinite(*ps)) ? std::optional<float>(*ps) : std::nullopt;
        *layer = pl ? tri(*pl != nullptr) : Tri::Unknown;
    }
    if (matches != 1) { *speed = std::nullopt; *layer = Tri::Unknown; return std::nullopt; }   // ambiguous or absent
    return value;
}

DoorSample ReEngineBridge::sample(ObjRef door) {
    DoorSample s;
    if (!ok_ || !build_gate_ok_) return s;
    void* d = by_ref(door);
    if (!d) return s;
    auto opened = bool_of(invoke(r_.door_is_opened, d));
    auto locked = bool_of(invoke(r_.door_is_locked, d));
    if (!opened || !locked) return s;
    s.readable = true;
    s.opened = tri(*opened);
    s.locked = tri(*locked);
    if (*opened) s.opened_side = side_of(invoke(r_.door_opened_side, d)).value_or(Side::Unknown);
    if (auto* rno = static_cast<int32_t*>(sdk_->field->get_data_raw(r_.door_peeked_rno, d, false))) s.routine = *rno;
    std::optional<float> speed;
    Tri layer = Tri::Unknown;
    s.value = peeked_value(d, s.opened_side, &speed, &layer);
    s.value_side = s.value ? s.opened_side : Side::Unknown;
    s.speed = speed;
    s.motion_layer = layer;
    return s;
}

}  // namespace re2net::adapter
